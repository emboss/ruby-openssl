require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestPKeyECDH < Test::Unit::TestCase
  def test_create
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    assert_not_nil(ecdh.public_key)
    assert_not_nil(ecdh.group)
    assert_equal(group, ecdh.group)
  end

  def test_regenerate_key
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    pub = ecdh.public_key
    ecdh.generate_key!
    pub2 = ecdh.public_key
    assert_equal(false, pub == pub2)
  end

  def test_to_der
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    der = ecdh.to_der
    assert_not_nil(OpenSSL::ASN1.decode(der))
  end

  def test_to_pem
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    assert_not_nil(ecdh.to_pem)
  end

  def test_to_text
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    assert_not_nil(ecdh.to_text)
  end

  def test_create_from_der
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    der = ecdh.to_der
    ecdh2 = OpenSSL::PKey::ECDH.new(der)
    assert_equal(der, ecdh2.to_der)
  end

  def test_create_from_pem
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    pem = ecdh.to_pem
    ecdh2 = OpenSSL::PKey::ECDH.new(pem)
    assert_equal(pem, ecdh2.to_pem)
  end

  def test_create_from_pem_pw
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    pem = ecdh.to_pem(OpenSSL::Cipher.new('AES-128-CBC'), 'secret')
    # pass password directly
    ecdh3 = OpenSSL::PKey::ECDH.new(pem, 'secret')
    assert_equal(ecdh.to_pem, ecdh3.to_pem)
  end

  def test_compute_key_block
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    ecdh2 = OpenSSL::PKey::ECDH.new(group)
    ecdh_secret = ecdh.compute_key(ecdh2.public_key, 128) do |secret, size|
      assert_equal(128, size)
      secret
    end
    ecdh2_secret = ecdh2.compute_key(ecdh.public_key, 128) do |secret, size|
      assert_equal(128, size)
      secret
    end
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_compute_key_default
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::ECDH.new(group)
    ecdh2 = OpenSSL::PKey::ECDH.new(group)
    ecdh_secret = ecdh.compute_key(ecdh2.public_key, 128)
    ecdh2_secret = ecdh2.compute_key(ecdh.public_key, 128)
    assert_equal(128, ecdh_secret.size)
    assert_equal(128, ecdh2_secret.size)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

end

end
