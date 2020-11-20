using System;

namespace PSJsonWebToken
{
    /// <summary>
    /// Contains a decoded Json Web Token header, payload and original signature.
    /// </summary>
    public class DecodedJsonWebToken
    {
        /// <summary>
        /// The JWT header deserialized as a JSON string.
        /// </summary>
        public string Header { get; set; }

        /// <summary>
        /// The JWT payload deserialized as a JSON string.
        /// </summary>
        public string Payload { get; set; }

        /// <summary>
        /// The original JWT signature.
        /// </summary>
        public string Signature { get; set; }

        /// <summary>
        /// Returns a formatted serialized JSON Web Key.
        /// </summary>
        /// <returns>The JWK as a formatted string.</returns>
        public override string ToString()
        {
            return (String.Format("{0}.{1}.{2}", Header, Payload, Signature));
        }
    }
}
