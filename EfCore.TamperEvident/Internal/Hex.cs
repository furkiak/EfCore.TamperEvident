namespace EfCore.TamperEvident.Internal
{
    /// <summary>Allocation-free lowercase hex encoding and decoding (the BCL only offers both from .NET 9 on).</summary>
    internal static class Hex
    {
        private const string Digits = "0123456789abcdef";

        public static string ToLower(ReadOnlySpan<byte> bytes)
        {
            Span<char> chars = bytes.Length <= 128 ? stackalloc char[bytes.Length * 2] : new char[bytes.Length * 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                chars[i * 2] = Digits[bytes[i] >> 4];
                chars[i * 2 + 1] = Digits[bytes[i] & 0xF];
            }

            return new string(chars);
        }

        /// <summary>Decodes exactly <c>destination.Length</c> bytes; upper and lower case digits are accepted.</summary>
        public static bool TryDecode(ReadOnlySpan<char> hex, Span<byte> destination)
        {
            if (hex.Length != destination.Length * 2)
            {
                return false;
            }

            for (var i = 0; i < destination.Length; i++)
            {
                var high = Value(hex[i * 2]);
                var low = Value(hex[i * 2 + 1]);
                if ((high | low) < 0)
                {
                    return false;
                }

                destination[i] = (byte)((high << 4) | low);
            }

            return true;
        }

        /// <inheritdoc cref="TryDecode(ReadOnlySpan{char}, Span{byte})"/>
        public static bool TryDecode(ReadOnlySpan<byte> utf8Hex, Span<byte> destination)
        {
            if (utf8Hex.Length != destination.Length * 2)
            {
                return false;
            }

            for (var i = 0; i < destination.Length; i++)
            {
                var high = Value((char)utf8Hex[i * 2]);
                var low = Value((char)utf8Hex[i * 2 + 1]);
                if ((high | low) < 0)
                {
                    return false;
                }

                destination[i] = (byte)((high << 4) | low);
            }

            return true;
        }

        public static bool IsLowerHex(ReadOnlySpan<byte> utf8)
        {
            foreach (var c in utf8)
            {
                if (c is not ((>= (byte)'0' and <= (byte)'9') or (>= (byte)'a' and <= (byte)'f')))
                {
                    return false;
                }
            }

            return true;
        }

        private static int Value(char c) => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => -1
        };
    }
}
