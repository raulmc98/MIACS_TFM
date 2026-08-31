"""
LSTM + Atención con masking correcto y embeddings para campos categóricos.

CAMBIOS CLAVE
-------------
1. Entrada doble: ids categóricos (int) + features numéricas (float).
2. event_code -> Embedding con mask_zero=True. Keras propaga la máscara
   automáticamente a través de Concatenate -> LSTM -> AttentionLayer,
   de modo que los timesteps de padding no contribuyen ni al estado
   oculto ni a los pesos de atención.
   Antes, con MAX_SEQ_LEN=1200 y secuencias de ~100 logs, más del 80% de
   los timesteps eran relleno procesado como si fuera dato real.
3. AttentionLayer aplica -1e9 a los scores enmascarados ANTES del softmax,
   por lo que los pesos suman 1 solo sobre los logs reales.
4. La capa es serializable (get_config) y no fija la longitud de secuencia.
"""

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    LSTM, Dense, Layer, Input, Embedding, Concatenate, Dropout
)

from Preprocesamiento_Logs.encode_event import (
    CATEGORICAL_FIELDS, CAT_VOCAB_SIZE, EVENT_CODE_VOCAB_SIZE, NUM_SIZE
)

from sklearn.metrics import classification_report, confusion_matrix

from Preprocesamiento_Logs.explain import explain_sequence

from collections import Counter

from tensorflow.keras import regularizers

# =========================================================
# ATENCIÓN CON MÁSCARA
# =========================================================

class AttentionLayer(Layer):
    """
    Atención aditiva sobre los timesteps del LSTM.
    Devuelve (context_vector, attention_weights).
    Los timesteps enmascarados reciben peso ~0.
    """

    def __init__(self, units=64, **kwargs):
        super().__init__(**kwargs)
        self.units = units
        self.supports_masking = True

    def build(self, input_shape):
        self.W = self.add_weight(
            name="att_W", shape=(input_shape[-1], self.units),
            initializer="glorot_uniform", trainable=True,
        )
        self.b = self.add_weight(
            name="att_b", shape=(self.units,),
            initializer="zeros", trainable=True,
        )
        self.V = self.add_weight(
            name="att_V", shape=(self.units, 1),
            initializer="glorot_uniform", trainable=True,
        )
        super().build(input_shape)

    def call(self, x, mask=None):
        # (batch, timesteps, units) -> (batch, timesteps, 1)
        score = tf.tanh(tf.tensordot(x, self.W, axes=1) + self.b)
        score = tf.tensordot(score, self.V, axes=1)

        if mask is not None:
            mask = tf.cast(tf.expand_dims(mask, -1), score.dtype)
            # -1e9 antes del softmax: el padding queda en peso ~0
            score += (1.0 - mask) * -1e9

        attention_weights = tf.nn.softmax(score, axis=1)
        context_vector = tf.reduce_sum(x * attention_weights, axis=1)

        return context_vector, attention_weights

    def compute_mask(self, inputs, mask=None):
        # El contexto ya está agregado: la máscara no se propaga más
        return None

    def get_config(self):
        config = super().get_config()
        config.update({"units": self.units})
        return config


# =========================================================
# MODELO
# =========================================================

def build_model(seq_len,
                n_cat_fields=len(CATEGORICAL_FIELDS),
                n_num_features=NUM_SIZE,
                event_code_dim=16,
                cat_dim=8,
                lstm_units=32,
                dropout=0.5):

    cat_input = Input(shape=(seq_len, n_cat_fields), dtype="int32", name="cat_input")
    num_input = Input(shape=(seq_len, n_num_features), dtype="float32", name="num_input")
    mask_input = Input(shape=(seq_len,), dtype="float32", name="mask_input")
    
    embeddings = []

    # event_code: vocabulario propio + mask_zero -> genera LA máscara
    ec = tf.keras.layers.Lambda(lambda t: t[:, :, 0], name="slice_event_code")(cat_input)
    embeddings.append(
        Embedding(input_dim=EVENT_CODE_VOCAB_SIZE,
                  output_dim=event_code_dim,
                  mask_zero=True,
                  name="emb_event_code")(ec)
    )

    # Resto de campos categóricos: hashing + embedding compartido por campo
    for i, field in enumerate(CATEGORICAL_FIELDS[1:], start=1):
        col = tf.keras.layers.Lambda(
            lambda t, idx=i: t[:, :, idx], name=f"slice_{field}"
        )(cat_input)
        embeddings.append(
            Embedding(input_dim=CAT_VOCAB_SIZE,
                      output_dim=cat_dim,
                      mask_zero=False,
                      name=f"emb_{field}")(col)
        )

    x = Concatenate(axis=-1)(embeddings + [num_input])

    bool_mask = tf.keras.layers.Lambda(
        lambda m: tf.cast(m, tf.bool), name="to_bool_mask"
    )(mask_input)

    # La máscara de emb_event_code se propaga sola hasta aquí
    lstm_out = LSTM(lstm_units, return_sequences=True, name="lstm")(x, mask=bool_mask)
    lstm_out = Dropout(dropout)(lstm_out)

    context, attention_weights = AttentionLayer(name="attention")(lstm_out, mask=bool_mask)
    context = Dropout(dropout)(context)

    output = Dense(1, activation="sigmoid", name="output",
               kernel_regularizer=regularizers.l2(1e-3))(context)


    inputs=[cat_input, num_input, mask_input]
    return Model(inputs, outputs=output), Model(inputs, attention_weights)


# =========================================================
# EJEMPLO DE USO
# =========================================================

if __name__ == "__main__":
    from sklearn.model_selection import train_test_split
    from tensorflow.keras.callbacks import EarlyStopping

    from Preprocesamiento_Logs.generate_dataset import (
        generate_train_dataset_raw, generate_test_dataset_raw, normalize_dataset
    )

    from Preprocesamiento_Logs.data_augmentation import augment_dataset_raw
    from Preprocesamiento_Logs.encode_event import preprocess_dataset, MAX_SEQ_LEN

    from sklearn.utils.class_weight import compute_class_weight
    import numpy as np


    # 1. Cargar RAW
    train_raw = generate_train_dataset_raw()
    labels = [l for _, l in train_raw]
    train_raw, val_raw = train_test_split(
        train_raw, test_size=0.2, stratify=labels, random_state=42
    )
    train_raw = augment_dataset_raw(train_raw, n_variants=2)   # solo train
    test_raw  = generate_test_dataset_raw()

    for name, ds in (("train", train_raw), ("test", test_raw)):
        labels = [l for _, l in ds]
        print(f"{name}: {len(ds)} secuencias (benignas={labels.count(0)}, maliciosas={labels.count(1)})")


    # 3. Normalizar (recalcula engineer_features sobre los datos aumentados)
    train = normalize_dataset(train_raw)
    test  = normalize_dataset(test_raw)

    lengths = [len(s) for s, _ in train]
    print(f"Longitud de secuencia: min={min(lengths)} p50={sorted(lengths)[len(lengths)//2]} max={max(lengths)} (MAX_SEQ_LEN={MAX_SEQ_LEN})")

    # 5. Vectorizar
    Xc_tr, Xn_tr, Xm_tr, y_tr = preprocess_dataset(train)
    Xc_te, Xn_te, Xm_te, y_te = preprocess_dataset(test)
    Xc_va, Xn_va, Xm_va, y_va = preprocess_dataset(val_raw)

    print(f"X_cat {Xc_tr.shape}  X_num {Xn_tr.shape}  y {y_tr.shape}")

    # 6. Entrenar
    model, attention_model = build_model(seq_len=Xc_tr.shape[1],
        lstm_units=32,
        dropout=0.5,
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=5e-4),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.AUC(name="auc"),
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
        ],
    )

    early_stop = EarlyStopping(
        monitor="val_auc", mode="max", patience=15, restore_best_weights=True
    )

    classes = np.unique(y_tr)
    weights = compute_class_weight("balanced", classes=classes, y=y_tr)
    class_weight = dict(zip(classes.astype(int), weights))
    print(class_weight)   # ≈ {0: 3.25, 1: 0.59}


    model.fit(
        [Xc_tr, Xn_tr, Xm_tr], y_tr,
        validation_data=([Xc_va, Xn_va, Xm_va], y_va),
        epochs=60,
        batch_size=8,
        callbacks=[early_stop],
        verbose=1,
        class_weight=class_weight
    )


    y_prob = model.predict([Xc_te, Xn_te, Xm_te], verbose=0).ravel()
    y_pred = (y_prob > 0.5).astype(int)

    print(confusion_matrix(y_te, y_pred))
    print(classification_report(y_te, y_pred, target_names=["benigna", "maliciosa"], digits=3))

    for label in (0, 1):
        codes = Counter(l["event_code"] for s, lab in train if lab == label for l in s)
        print(f"\nlabel={label}: {codes.most_common(12)}")

    # solo_mal = set(c for c, _ in codes.items()) # ejecútalo por separado y compara los sets

    for seq, label in test:            # test ya normalizado
        print("=" * 70, f"\nEtiqueta real: {label}")
        explain_sequence(model, attention_model, seq, top_n=15)