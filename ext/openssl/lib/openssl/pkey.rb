module OpenSSL::PKey
  module KeyDerivation
    class << self
      def ansi_x963(digest, shared_info=nil)
        Proc.new do |secret, size|
          if size < 0 || size % 8 != 0
            raise ArgumentError.new('Key bit size must be positive and a multiple of 8')
          end

          bit_size = size / 8
          counter = 1
          iterations = bit_size / digest.digest_length + 1
          if iterations > (1 << 32) - 1
            raise ArgumentError.new('Key bit size too large')
          end
          retval = String.new

          iterations.times do
            digest << secret
            digest << [ counter ].pack('N')
            digest << shared_info if shared_info
            retval << digest.digest
            digest.reset
            counter += 1
          end

          str_erase(secret)
          retval[0..bit_size-1]
        end
      end

      def ecc_cms_shared_info(key_encryption, digest, ukm=nil)
        Proc.new do |secret, size|
          alg_id = key_encryption.respond_to?(:to_der) ?
                   key_encryption :
                   OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(key_encryption)])
          size_der = OpenSSL::ASN1::OctetString.new( [ size ].pack('N'))
          explicit_size = OpenSSL::ASN1::ASN1Data.new([size_der], 2, :CONTEXT_SPECIFIC)

          seq = [alg_id]

          if ukm
            ukm_der = OpenSSL::ASN1::OctetString.new(ukm)
            seq << OpenSSL::ASN1::ASN1Data.new([ukm_der], 0, :CONTEXT_SPECIFIC)
          end

          seq << explicit_size
          shared_info = OpenSSL::ASN1::Sequence.new(seq).to_der
          ansi_x963(digest, shared_info).call(secret, size)
        end
      end

      def nist_800_56a_concatenation(digest, other_info)
        Proc.new do |secret, size|
          if size < 0 || size % 8 != 0
            raise ArgumentError.new('Key bit size must be positive and a multiple of 8')
          end

          bit_size = size / 8
          counter = 1
          iterations = bit_size / digest.digest_length + 1
          if iterations > (1 << 32) - 1
            raise ArgumentError.new('Key bit size too large')
          end
          retval = String.new

          iterations.times do
            digest << [ counter ].pack('N')
            digest << secret
            digest << other_info
            retval << digest.digest
            digest.reset
            counter += 1
          end

          str_erase(secret)
          retval[0..bit_size-1]
        end
      end

      private

      def str_erase(str)
        for i in 0..str.size-1 do
          str[i] = "\x0"
        end
      end
    end
  end
end
