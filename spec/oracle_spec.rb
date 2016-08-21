require 'oracle'
require 'cipher'

RSpec.describe Oracle do
  describe '#attack' do
    it 'decrypts DES ciphertexts with a length that is a multiple of block size' do
      cipher = Cipher.new('DES-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('123456781234567812345678')

      expect(oracle.attack(ciphertext)).to eq("1234567812345678\x8\x8\x8\x8\x8\x8\x8\x8")
    end

    it 'decrypts DES ciphertexts with a length that is not a multiple of block size' do
      cipher = Cipher.new('DES-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('12345678123456781234')

      expect(oracle.attack(ciphertext)).to eq("123456781234\x4\x4\x4\x4")
    end

    it 'decrypts AES ciphertexts with a length that is a multiple of block size' do
      cipher = Cipher.new('AES-128-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('123456781234567812345678')

      expect(oracle.attack(ciphertext)).to eq("12345678\x8\x8\x8\x8\x8\x8\x8\x8")
    end

    it 'decrypts AES ciphertexts with a length that is not a multiple of block size' do
      cipher = Cipher.new('AES-128-CBC')
      oracle = Oracle.new(cipher)
      ciphertext = cipher.encrypt('12345678123456781234')

      expect(oracle.attack(ciphertext)).to eq("1234\xc\xc\xc\xc\xc\xc\xc\xc\xc\xc\xc\xc")
    end
  end
end
