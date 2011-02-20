require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestPKeyDSA < Test::Unit::TestCase
  def test_read_private_key_der
    key = OpenSSL::PKey::DSA.new(512)
    der = key.to_der
    key2 = OpenSSL::PKey.read_private(der)
    assert(key2.private?)
    assert_equal(der, key2.to_der)
  end

  def test_read_private_key_pem
    key = OpenSSL::PKey::DSA.new(512)
    pem = key.to_pem
    key2 = OpenSSL::PKey.read_private(pem)
    assert(key2.private?)
    assert_equal(pem, key2.to_pem)
  end

  def test_read_public_key_der
    key = OpenSSL::PKey::DSA.new(512).public_key
    der = key.to_der
    key2 = OpenSSL::PKey.read_private(der)
    assert(key2.private?)
    assert_equal(der, key2.to_der)
  end

  def test_read_public_key_pem
    key = OpenSSL::PKey::DSA.new(512).public_key
    pem = key.to_pem
    key2 = OpenSSL::PKey.read_public(pem)
    assert(!key2.private?)
    assert_equal(pem, key2.to_pem)
  end

  def test_read_private_key_pem_pw
    key = OpenSSL::PKey::DSA.new(512)
    pem = key.to_pem(OpenSSL::Cipher.new('AES-128-CBC'), 'secret')
    #callback form for password
    key2 = OpenSSL::PKey.read_private(pem) do
      'secret'
    end
    assert(key2.private?)
    # pass password directly
    key2 = OpenSSL::PKey.read_private(pem, 'secret')
    assert(key2.private?)
    #omit pem equality check, will be different due to cipher iv
  end

end

end