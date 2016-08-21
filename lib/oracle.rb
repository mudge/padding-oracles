class Oracle
  attr_reader :cipher

  def initialize(cipher)
    @cipher = cipher
  end

  def attack(ciphertext)
    ciphertext_blocks = cipher.split(ciphertext)

    # Let the attack commence!
    # Take each pair of blocks and attack them in turn (note that this skips the first block
    # as we can't recover that without guessing the IV)
    ciphertext_blocks.each_cons(2).flat_map { |previous_block, target_block|

      # Create an empty block which we will populate with the decrypted plain text
      m = Array.new(cipher.block_size)

      # Decrypt each byte of the block starting from the end and working backwards
      cipher.block_size.pred.downto(0).each do |i|

        # The appropriate pad for this iteration (e.g. 1, 2, 3, 4, 5, 6, 7, 8)
        pad = cipher.block_size - i

        # The size of the padding for this iteration (e.g. to pad with (2, 2), (3, 3, 3), etc.)
        padding_size = cipher.block_size - i - 1

        # The bytes before the one we're trying to decrypt
        butlast = previous_block[0, i]

        # Generate the padding for this iteration
        padding = padding_size.downto(1).map { |j| previous_block[cipher.block_size - j] ^ m[cipher.block_size - j] ^ pad }

        # The key bit: exhaustively guess this byte by trying 0-255 and checking if it is a valid padding
        # Also handle the special case when decrypting the truly final block which will already have
        # valid padding: check that the pad and the guess are not the same and default to the pad if so.
        m[i] = (0..255).find { |g|
          crafted_ciphertext = butlast + [previous_block[i] ^ g ^ pad] + padding + target_block

          cipher.valid_padding?(crafted_ciphertext.pack('C*')) && pad != g
        } || pad
      end

      m
    }.pack('C*')
  end
end
