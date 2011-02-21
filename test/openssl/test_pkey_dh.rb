require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestPKeyDH < Test::Unit::TestCase
  def test_dup_pub_key
    dh = OpenSSL::PKey::DH.generate(128)
    assert(dh.pub_key)
    assert(dh.public_key.pub_key)
  end
end

end
