import pyhon_uECC

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

curve = uECC_Curve_t();
ma_courbe = pyhon_uECC.PyuECC(curve);
print("mon nombre initiale " + ma_courbe.initialize(3))
print("ma cle privee " + ma_courbe.getPrivateKey())
print("ma cle public " + ma_courbe.getPublicKey())
