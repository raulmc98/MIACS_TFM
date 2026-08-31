"""
Arquitectura del clasificador de sesiones: LSTM + atención con enmascaramiento.

Este módulo contiene únicamente la definición del modelo. El entrenamiento y la
evaluación se realizan desde `cross_validate.py` (validación cruzada y contraste
por permutación) y `explicabilidad.py` (análisis del mecanismo de atención).

ENTRADAS
--------
El modelo recibe tres tensores:

    cat_input   (batch, seq_len, n_cat)   int32    ids categóricos
    num_input   (batch, seq_len, n_num)   float32  características numéricas
    mask_input  (batch, seq_len)          float32  1.0 = evento real, 0.0 = relleno

La máscara se suministra de forma EXPLÍCITA en lugar de derivarla mediante
`mask_zero=True` en la capa de proyección. La propagación automática de Keras no
atraviesa la concatenación con `num_input` —que carece de máscara—, de modo que
la capa de atención recibía `mask=None` y repartía peso sobre los pasos de
relleno. Con MAX_SEQ_LEN=1200 y secuencias reales de 199 a 1157 eventos, eso
suponía que hasta el 98 % de la masa de atención recaía sobre posiciones
inexistentes.

SALIDAS
-------
`build_model` devuelve dos modelos que comparten pesos:

    model             -> probabilidad de que la sesión sea maliciosa
    attention_model   -> peso de atención de cada paso temporal
"""

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    LSTM, Dense, Layer, Input, Embedding, Concatenate, Dropout
)
from tensorflow.keras import regularizers

from Preprocesamiento_Logs.encode_event import (
    CATEGORICAL_FIELDS, CAT_VOCAB_SIZE, EVENT_CODE_VOCAB_SIZE, NUM_SIZE
)


# =========================================================
# ATENCIÓN CON MÁSCARA
# =========================================================

class AttentionLayer(Layer):
    """
    Atención aditiva sobre los pasos temporales del LSTM.

    Devuelve (context_vector, attention_weights). Los pasos enmascarados
    reciben un score de -1e9 ANTES del softmax, por lo que su peso resultante
    es ~0 y los pesos suman 1 únicamente sobre los eventos reales. Sin esta
    exclusión los pesos no son comparables entre sesiones de distinta longitud.
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
        # (batch, timesteps, features) -> (batch, timesteps, 1)
        score = tf.tanh(tf.tensordot(x, self.W, axes=1) + self.b)
        score = tf.tensordot(score, self.V, axes=1)

        if mask is not None:
            mask = tf.cast(tf.expand_dims(mask, -1), score.dtype)
            score += (1.0 - mask) * -1e9

        attention_weights = tf.nn.softmax(score, axis=1)
        context_vector = tf.reduce_sum(x * attention_weights, axis=1)

        return context_vector, attention_weights

    def compute_mask(self, inputs, mask=None):
        # El contexto ya está agregado sobre el eje temporal: no se propaga
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
    """
    Construye el clasificador y el modelo auxiliar de atención.

    Los valores por defecto de `lstm_units` y `dropout` corresponden a la
    configuración definitiva reportada en la memoria.
    """

    cat_input  = Input(shape=(seq_len, n_cat_fields),   dtype="int32",   name="cat_input")
    num_input  = Input(shape=(seq_len, n_num_features), dtype="float32", name="num_input")
    mask_input = Input(shape=(seq_len,),                dtype="float32", name="mask_input")

    embeddings = []

    # El identificador de evento tiene vocabulario explícito: es el campo de
    # mayor poder discriminante y no debe sufrir colisiones por dispersión.
    ec = tf.keras.layers.Lambda(
        lambda t: t[:, :, 0], name="slice_event_code"
    )(cat_input)
    embeddings.append(
        Embedding(input_dim=EVENT_CODE_VOCAB_SIZE,
                  output_dim=event_code_dim,
                  mask_zero=True,
                  name="emb_event_code")(ec)
    )

    # Resto de campos categóricos: dispersión a CAT_VOCAB_SIZE cubos,
    # con una proyección independiente por campo.
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

    # Máscara explícita: se pasa a mano al LSTM y a la capa de atención
    bool_mask = tf.keras.layers.Lambda(
        lambda m: tf.cast(m, tf.bool), name="to_bool_mask"
    )(mask_input)

    lstm_out = LSTM(lstm_units, return_sequences=True, name="lstm")(x, mask=bool_mask)
    lstm_out = Dropout(dropout)(lstm_out)

    context, attention_weights = AttentionLayer(name="attention")(lstm_out, mask=bool_mask)
    context = Dropout(dropout)(context)

    output = Dense(1, activation="sigmoid", name="output",
                   kernel_regularizer=regularizers.l2(1e-3))(context)

    inputs = [cat_input, num_input, mask_input]

    return Model(inputs, outputs=output), Model(inputs, attention_weights)