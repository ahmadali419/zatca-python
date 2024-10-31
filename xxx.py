from cryptography.hazmat.primitives.asymmetric import ec

# List of supported curves
supported_curves = [
    ec.SECP256R1(),
    ec.SECP384R1(),
    ec.SECP521R1(),
    ec.SECP256K1(),  # This is the curve you are using
]

for curve in supported_curves:
    print(curve.name)

