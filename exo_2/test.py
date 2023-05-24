import pyhon_uECC.c
import binascii

# Déclaration de la classe uECC_Curve_t
class uECC_Curve_t:
    pass

# Définition de la classe uECC_CurveWrapper
class uECC_CurveWrapper:
    def __init__(self, curve: uECC_Curve_t):
        self.curve = curve

# # Définition de la classe uECC_HashContextWrapper
# class uECC_HashContextWrapper:
#     def __init__(self, context: uECC_HashContext):
#         self.context = context

binary_string= binascii.unhexlify("4b8e29b9b0dddd58a709edba7d6df6c07ebdaf5653e325114bc5318c238f87f0")
curve = uECC_Curve_t()
ma_courbe = pyhon_uECC.PyuECC(curve)
print("mon nombre initiale " + ma_courbe.initialize(binary_string))
print("ma cle privee " + ma_courbe.getPrivateKey())
print("ma cle public " + ma_courbe.getPublicKey())
