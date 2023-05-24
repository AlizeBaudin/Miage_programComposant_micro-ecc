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
    const struct uECC_Curve_t* curve;
};

/* Définition de la classe uECC_HashContextWrapper */
struct uECC_HashContextWrapper {
    const uECC_HashContext* context;
};


class PyuECC : public uECC_CurveWrapper
{
    public:
        using uECC_CurveWrapper::uECC_CurveWrapper;
        uECC(uECC_CurveWrapper curve) : m_curve(curve){};
        ~uECC() {};
        
       
        void initialize(int number) override {
	        PYBIND11_OVERRIDE_PURE(
                int, /* Return type */
                uECC_CurveWrapper,      /* Parent class */
                uECC_secp160r1,          /* Name of function in C++ (must match Python name) */
            );
       	}

        void getPrivateKey() override {
	       	PYBIND11_OVERRIDE_PURE(
                int, /* Return type */
                uECC_CurveWrapper,      /* Parent class */
                uECC_curve_private_key_size ,          /* Name of function in C++ (must match Python name) */
                m_curve      /* Argument(s) */
            );
       	}

        void getPublicKey() override {
	       	PYBIND11_OVERRIDE_PURE(
                int, /* Return type */
                uECC_CurveWrapper,      /* Parent class */
                uECC_curve_public_key_size,          /* Name of function in C++ (must match Python name) */
                m_curve      /* Argument(s) */
            );
       	}

    private :
        uECC_CurveWrapper m_curve;
};
 
namespace py = pybind11;

PYBIND11_MODULE(python_uECC, m) {
    //m.doc() = "greeting_object 1.0";
    
    py::class_<uECC_CurveWrapper, PyuECC>(m, "uECC_CurveWrapper",py::dynamic_attr())
        .def(py::init<>())
        .def("initialize", &PyuECC::initialize)
        .def("getPrivateKey", &PyuECC::getPrivateKey)
        .def("getPublicKey", &PyuECC::getPublicKey);

    m.def("getPrivateKey", &getPrivateKey, "a function returning the private key");
    m.def("getPublicKey", &getPublicKey, "a function returning the public key");
    m.def("initialize", &initialize, "a function returning a number");
  
}

