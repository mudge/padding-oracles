require 'oracle'
require 'cipher'

RSpec.describe Oracle do
  describe '#attack' do
    it 'decrypts DES ciphertexts with a length that is a multiple of block size' do
      cipher = Cipher.new('DES-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('012345670123456701234567')

      expect(oracle.attack(ciphertext)).to eq("0123456701234567\x8\x8\x8\x8\x8\x8\x8\x8")
    end

    it 'decrypts DES ciphertexts with a length that is not a multiple of block size' do
      cipher = Cipher.new('DES-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('01234567012345670123')

      expect(oracle.attack(ciphertext)).to eq("012345670123\x4\x4\x4\x4")
    end

    it 'decrypts AES ciphertexts with a length that is a multiple of block size' do
      cipher = Cipher.new('AES-128-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('0123456789abcdef0123456789abcdef')

      expect(oracle.attack(ciphertext)).to eq("0123456789abcdef\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
    end

    it 'decrypts AES ciphertexts with a length that is not a multiple of block size' do
      cipher = Cipher.new('AES-128-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('0123456789abcdef0123456789abcdef01234567')

      expect(oracle.attack(ciphertext)).to eq("0123456789abcdef01234567\x8\x8\x8\x8\x8\x8\x8\x8")
    end
  end
end
