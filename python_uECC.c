#include "/home/alize_baudinbianchini75/Miage_programComposant_micro-ecc/uECC.h"
#include "/home/alize_baudinbianchini75/Miage_programComposant_micro-ecc/uECC_vli.h"

//#include "/home/alize_baudinbianchini75/Miage_programComposant_micro-ecc/pybind11.h"
#include <pybind11/pybind11.h>
#include <pybind11/bytes.h>
#include <pybind11/stl.h>
#include <stdint.h>


/* Déclaration de la structure uECC_Curve_t */
struct uECC_Curve_t;

/* Définition de la classe uECC_CurveWrapper */
struct uECC_CurveWrapper {
    const uECC_Curve_t* curve;
};

/* Définition de la classe uECC_HashContextWrapper */
struct uECC_HashContextWrapper {
    const uECC_HashContext* context;
};


Class uECC : public uECC_secp160r1(), uECC_curve_public_key_size(uECC_Curve curve), uECC_curve_public_key_size(uECC_Curve curve)
{
    public:
        uECC() {};
        ~uECC() {};
        
        using uECC_secp160r1();
        using uECC_curve_private_key_size(uECC_Curve curve);
        using uECC_curve_public_key_size(uECC_Curve curve);

        void initialize() override {
	        PYBIND11_OVERRIDE_PURE(
                int, /* Return type */
                uECC_secp160r1(),      /* Parent class */
                uECC_secp160r1,          /* Name of function in C++ (must match Python name) */
            );
       	}

        void getPrivateKey() override {
	       	PYBIND11_OVERRIDE_PURE(
                std::string, /* Return type */
                Animal,      /* Parent class */
                go,          /* Name of function in C++ (must match Python name) */
                n_times      /* Argument(s) */
            );
       	}

        void getPublicKey() override {
	       	PYBIND11_OVERRIDE_PURE(
                std::string, /* Return type */
                Animal,      /* Parent class */
                go,          /* Name of function in C++ (must match Python name) */
                n_times      /* Argument(s) */
            );
       	}


};
 
namespace py = pybind11;

PYBIND11_MODULE(uECC, m) {
    py::class_<uECC_CurveWrapper>(m, "uECC_Curve")
        .def(py::init<>())
        .def_readonly("curve", &uECC_CurveWrapper::curve);

    py::class_<uECC_HashContextWrapper>(m, "uECC_HashContext")
        .def(py::init<>())
        .def_readonly("context", &uECC_HashContextWrapper::context);


    m.def("uECC_secp160r1", &uECC_secp160r1) {
        return uECC_secp160r1();
    };

   
    m.def("uECC_set_rng", [](py::function rng_func) {
        // Fonction de rappel Pybind11 pour la génération de nombres aléatoires
        auto callback = [rng_func](uint8_t *dest, unsigned size) -> int {
            // Appeler la fonction de rappel Python pour générer des nombres aléatoires
            py::gil_scoped_acquire acquire;
            py::bytes result = rng_func(size);
            std::memcpy(dest, result.data(), size);
            return 1;
        };
        
        // Appeler la fonction uECC_set_rng avec la fonction de rappel personnalisée
        uECC_set_rng(callback);
    });


    m.def("uECC_get_rng", []() {
        return uECC_get_rng();
    });

    m.def("uECC_curve_private_key_size", [](uECC_Curve curve) {
        return uECC_curve_private_key_size(curve);
    });

    m.def("uECC_curve_public_key_size", [](uECC_Curve curve) {
        return uECC_curve_public_key_size(curve);
    });

 
    m.def("uECC_make_key", [](py::bytes public_key, py::bytes private_key, uECC_Curve curve) {
        if (public_key.size() != uECC_curve_public_key_size(curve)) {
            throw std::runtime_error("Invalid size for public_key");
        }
        if (private_key.size() != uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for private_key");
        }
        return uECC_make_key(reinterpret_cast<uint8_t*>(public_key.mutable_data()),
                             reinterpret_cast<uint8_t*>(private_key.mutable_data()),
                             curve);
    });

    m.def("uECC_shared_secret", [](py::bytes public_key, py::bytes private_key, uECC_Curve curve) {
        if (public_key.size() != uECC_curve_public_key_size(curve)) {
            throw std::runtime_error("Invalid size for public_key");
        }
        if (private_key.size() != uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for private_key");
        }
        uint8_t secret[uECC_curve_private_key_size(curve)];
        int result = uECC_shared_secret(reinterpret_cast<const uint8_t*>(public_key.data()),
                                        reinterpret_cast<const uint8_t*>(private_key.data()),
                                        secret,
                                        curve);
        if (result == 0) {
            throw std::runtime_error("Error computing shared secret");
        }
        return py::bytes(reinterpret_cast<const char*>(secret), uECC_curve_private_key_size(curve));
    });

#if uECC_SUPPORT_COMPRESSED_POINT
    m.def("uECC_compress", [](py::bytes public_key, uECC_Curve curve) {
        if (public_key.size() != uECC_curve_public_key_size(curve)) {
            throw std::runtime_error("Invalid size for public_key");
        }
        uint8_t compressed[uECC_curve_public_key_size(curve) + 1];
        uECC_compress(reinterpret_cast<const uint8_t*>(public_key.data()),
                      compressed,
                      curve);
        return py::bytes(reinterpret_cast<const char*>(compressed), uECC_curve_public_key_size(curve) + 1);
    });

    m.def("uECC_decompress", [](py::bytes compressed, uECC_Curve curve) {
        if (compressed.size() != uECC_curve_public_key_size(curve) + 1) {
            throw std::runtime_error("Invalid size for compressed");
        }
        uint8_t public_key[uECC_curve_public_key_size(curve)];
        uECC_decompress(reinterpret_cast<const uint8_t*>(compressed.data()),
                        public_key,
                        curve);
        return py::bytes(reinterpret_cast<const char*>(public_key), uECC_curve_public_key_size(curve));
    });
#endif /* uECC_SUPPORT_COMPRESSED_POINT */

    m.def("uECC_valid_public_key", [](py::bytes public_key, uECC_Curve curve) {
        if (public_key.size() != uECC_curve_public_key_size(curve)) {
            throw std::runtime_error("Invalid size for public_key");
        }
        return uECC_valid_public_key(reinterpret_cast<const uint8_t*>(public_key.data()), curve);
    });

    m.def("uECC_compute_public_key", [](py::bytes private_key, uECC_Curve curve) {
        if (private_key.size() != uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for private_key");
        }
        uint8_t public_key[uECC_curve_public_key_size(curve)];
        int result = uECC_compute_public_key(reinterpret_cast<const uint8_t*>(private_key.data()),
                                             public_key,
                                             curve);
        if (result == 0) {
            throw std::runtime_error("Error computing public key");
        }
        return py::bytes(reinterpret_cast<const char*>(public_key), uECC_curve_public_key_size(curve));
    });
    m.def("uECC_sign", [](py::bytes private_key, py::bytes message_hash, unsigned hash_size, uECC_Curve curve) {
        if (private_key.size() != uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for private_key");
        }
        if (message_hash.size() != hash_size) {
            throw std::runtime_error("Invalid size for message_hash");
        }
        uint8_t signature[2 * uECC_curve_private_key_size(curve)];
        int result = uECC_sign(reinterpret_cast<const uint8_t*>(private_key.data()),
                               reinterpret_cast<const uint8_t*>(message_hash.data()),
                               hash_size,
                               signature,
                               curve);
        if (result == 0) {
            throw std::runtime_error("Error generating signature");
        }
        return py::bytes(reinterpret_cast<const char*>(signature), 2 * uECC_curve_private_key_size(curve));
    });

    py::class_<uECC_HashContextWrapper>(m, "uECC_HashContext")
        .def(py::init<>())
        .def_readonly("context", &uECC_HashContextWrapper::context);

    m.def("uECC_sign_deterministic", [](py::bytes private_key, py::bytes message_hash, uECC_HashContextWrapper context, uECC_Curve curve) {
        if (private_key.size() != uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for private_key");
        }
        if (message_hash.size() != context.context->result_size) {
            throw std::runtime_error("Invalid size for message_hash");
        }
        uint8_t signature[2 * uECC_curve_private_key_size(curve)];
        int result = uECC_sign_deterministic(reinterpret_cast<const uint8_t*>(private_key.data()),
                                             reinterpret_cast<const uint8_t*>(message_hash.data()),
                                             context.context,
                                             signature,
                                             curve);
        if (result == 0) {
            throw std::runtime_error("Error generating deterministic signature");
        }
        return py::bytes(reinterpret_cast<const char*>(signature), 2 * uECC_curve_private_key_size(curve));
    });

    m.def("uECC_init_hash", [](uECC_HashContextWrapper context) {
        context.context->init_hash(context.context);
    });

    m.def("uECC_update_hash", [](uECC_HashContextWrapper context, py::bytes message) {
        context.context->update_hash(context.context, reinterpret_cast<const uint8_t*>(message.data()), message.size());
    });

    m.def("uECC_finish_hash", [](uECC_HashContextWrapper context) {
        uint8_t hash_result[context.context->result_size];
        context.context->finish_hash(context.context, hash_result);
        return py::bytes(reinterpret_cast<const char*>(hash_result), context.context->result_size);
    });

    m.def("uECC_sign_deterministic", [](py::bytes private_key, py::bytes message_hash, unsigned hash_size, py::bytes hash_context, uECC_Curve curve) {
        if (private_key.size() != uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for private_key");
        }
        if (message_hash.size() != hash_size) {
            throw std::runtime_error("Invalid size for message_hash");
        }
        if (hash_context.size() != sizeof(uECC_HashContext)) {
            throw std::runtime_error("Invalid size for hash_context");
        }
        uint8_t signature[2 * uECC_curve_private_key_size(curve)];
        int result = uECC_sign_deterministic(reinterpret_cast<const uint8_t*>(private_key.data()),
                                             reinterpret_cast<const uint8_t*>(message_hash.data()),
                                             hash_size,
                                             reinterpret_cast<const uECC_HashContext*>(hash_context.data()),
                                             signature,
                                             curve);
        if (result == 0) {
            throw std::runtime_error("Error generating deterministic signature");
        }
        return py::bytes(reinterpret_cast<const char*>(signature), 2 * uECC_curve_private_key_size(curve));
    });

    m.def("uECC_verify", [](py::bytes public_key, py::bytes message_hash, unsigned hash_size, py::bytes signature, uECC_Curve curve) {
        if (public_key.size() != uECC_curve_public_key_size(curve)) {
            throw std::runtime_error("Invalid size for public_key");
        }
        if (message_hash.size() != hash_size) {
            throw std::runtime_error("Invalid size for message_hash");
        }
        if (signature.size() != 2 * uECC_curve_private_key_size(curve)) {
            throw std::runtime_error("Invalid size for signature");
        }
        int result = uECC_verify(reinterpret_cast<const uint8_t*>(public_key.data()),
                                 reinterpret_cast<const uint8_t*>(message_hash.data()),
                                 hash_size,
                                 reinterpret_cast<const uint8_t*>(signature.data()),
                                 curve);
        return result == 1;
    });
    
}

