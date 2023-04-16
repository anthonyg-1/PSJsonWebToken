using System;

namespace PSJsonWebToken
{
    /// <summary>
    /// Contains a public keys in PEM format converted from a JWK
    /// </summary>
    public class PemFromJwkResult
    {
        /// <summary>
        /// The JWK ID as a string.
        /// </summary>
        public string JwkIdentifier { get; set; }

        /// <summary>
        /// The public key as a formatted PEM
        /// </summary>
        public string Pem { get; set; }

        /// <summary>
        /// The public key as an unformatted base64 certificate
        /// </summary>
        public string PublicKeyUnformatted { get; set; }
    }
}
