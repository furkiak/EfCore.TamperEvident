using System.Buffers;
using System.Text.Json;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Reads a large JSON document from a stream token by token, without loading it into memory, and hands out complete
    /// values (for example one audit entry) as raw bytes. Only the value being read has to fit into memory.
    /// </summary>
    internal sealed class JsonStreamReader : IDisposable
    {
        private readonly Stream _stream;
        private byte[] _buffer;
        private int _offset;
        private int _length;
        private bool _endOfStream;
        private JsonReaderState _state;
        private int _pin = -1;

        public JsonStreamReader(Stream stream, int bufferSize = 64 * 1024)
        {
            _stream = stream;
            _buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
            _state = new JsonReaderState(new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, MaxDepth = 256 });
        }

        public JsonTokenType TokenType { get; private set; }

        /// <summary>The depth of the current token (0 for the root value).</summary>
        public int Depth { get; private set; }

        /// <summary>The value of the current property name or string token.</summary>
        public string? String { get; private set; }

        private int TokenStart { get; set; }

        /// <summary>Moves to the next token. Returns <c>false</c> at the end of the document.</summary>
        public async ValueTask<bool> ReadAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                if (TryRead())
                {
                    return true;
                }

                if (_endOfStream)
                {
                    return false;
                }

                await FillAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Returns the bytes of the value the reader is positioned on (an object, an array or a primitive) and moves past it.
        /// </summary>
        public async ValueTask<ReadOnlyMemory<byte>> ReadValueAsync(CancellationToken cancellationToken)
        {
            if (TokenType is not (JsonTokenType.StartObject or JsonTokenType.StartArray))
            {
                return _buffer.AsMemory(TokenStart, _offset - TokenStart).ToArray();
            }

            // Keep everything from the start token on in the buffer until the matching end token was read.
            _pin = TokenStart;
            var depth = Depth;
            try
            {
                while (await ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (Depth == depth && TokenType is JsonTokenType.EndObject or JsonTokenType.EndArray)
                    {
                        return _buffer.AsMemory(_pin, _offset - _pin).ToArray();
                    }
                }

                throw new JsonException("The JSON document ended in the middle of a value.");
            }
            finally
            {
                _pin = -1;
            }
        }

        /// <summary>Skips the value the reader is positioned on.</summary>
        public async ValueTask SkipAsync(CancellationToken cancellationToken)
        {
            if (TokenType is not (JsonTokenType.StartObject or JsonTokenType.StartArray))
            {
                return;
            }

            var depth = Depth;
            while (await ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (Depth == depth && TokenType is JsonTokenType.EndObject or JsonTokenType.EndArray)
                {
                    return;
                }
            }
        }

        private bool TryRead()
        {
            var reader = new Utf8JsonReader(_buffer.AsSpan(_offset, _length - _offset), _endOfStream, _state);
            if (!reader.Read())
            {
                return false;
            }

            TokenType = reader.TokenType;
            Depth = reader.CurrentDepth;
            TokenStart = _offset + (int)reader.TokenStartIndex;
            String = reader.TokenType is JsonTokenType.PropertyName or JsonTokenType.String ? reader.GetString() : null;
            _offset += (int)reader.BytesConsumed;
            _state = reader.CurrentState;
            return true;
        }

        private async ValueTask FillAsync(CancellationToken cancellationToken)
        {
            // Move the bytes that are still needed to the front, growing the buffer when a pinned value fills it.
            var keep = _pin >= 0 ? Math.Min(_pin, _offset) : _offset;
            var remaining = _length - keep;
            if (remaining >= _buffer.Length / 2)
            {
                var larger = ArrayPool<byte>.Shared.Rent(_buffer.Length * 2);
                Buffer.BlockCopy(_buffer, keep, larger, 0, remaining);
                ArrayPool<byte>.Shared.Return(_buffer);
                _buffer = larger;
            }
            else if (keep > 0)
            {
                Buffer.BlockCopy(_buffer, keep, _buffer, 0, remaining);
            }

            _offset -= keep;
            TokenStart -= keep;
            if (_pin >= 0)
            {
                _pin -= keep;
            }

            _length = remaining;
            var read = await _stream.ReadAsync(_buffer.AsMemory(_length), cancellationToken).ConfigureAwait(false);
            _length += read;
            _endOfStream = read == 0;
        }

        public void Dispose() => ArrayPool<byte>.Shared.Return(_buffer);
    }
}
