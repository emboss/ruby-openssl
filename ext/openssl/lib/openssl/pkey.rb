module OpenSSL::PKey
  module KDF
    ANSI_X963_SHA1 = Proc.new do |secret, size|
      if size < 0 || size % 8 != 0
        raise ArgumentError.new("Key bit size must be positive and a multiple of 8.")
      end

      bit_size = size / 8
      counter = 1
      digest = OpenSSL::Digest::SHA1.new
      iterations = bit_size / digest.digest_length + 1
      retval = String.new

      iterations.times do
        digest << secret
        digest << [ counter ].pack('N')
        retval << digest.digest
        digest.reset
        counter += 1
      end

      retval[0..bit_size-1]
    end
  end
end
