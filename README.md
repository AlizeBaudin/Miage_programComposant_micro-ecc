# Miage_programComposant_micro-ecc
ECDH and ECDSA for 8-bit, 32-bit, and 64-bit processors.

# Présentation exercice TP2 : faire une composnte python
ouvrir le dossier "exo_2" <br>

## python_uECC.c
création de la class c pour la traduire en python <br>
inspiré du site : https://pybind11.readthedocs.io/en/stable/advanced/classes.html <br>
et du git : https://github.com/jluuM2/python_cle_publique_2023/tree/main/voiture <br>

## test.py 
création de la composante python qui va exécuter la class de python_uECC
introduction de la bibliothèque "binascii" qui convertit  les buffers binaires en chaines de caractères en hexadécimal <br>
Code : <br>
  import binascii <br>
  binary_string=binascii.unhexlify("4b8e29b9b0dddd58a709edba7d6df6c07ebdaf5653e325114bc5318c238f87f0") <br>

## Makefile
le makefile issue du github de jluuM2
                                                                                     
