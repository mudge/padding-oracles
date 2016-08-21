require 'openssl'

class Cipher
  attr_reader :type, :block_size
  attr_accessor :key, :iv

  def initialize(type)
    @type = type
    cipher = build_cipher
    @key = cipher.random_key
    @iv = cipher.random_iv
    @block_size = cipher.block_size
  end

  def encrypt(message)
    cipher = build_cipher
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    cipher.update(message) + cipher.final
  end

  def valid_padding?(ciphertext)
    decrypt(ciphertext)
  rescue OpenSSL::Cipher::CipherError
    false
  end

  def decrypt(ciphertext)
    cipher = build_cipher
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    cipher.update(ciphertext) + cipher.final
  end

  def split(bytestring)
    bytestring.unpack('C*').each_slice(block_size).entries
  end

  private

  def build_cipher
    OpenSSL::Cipher.new(type)
  end
end
