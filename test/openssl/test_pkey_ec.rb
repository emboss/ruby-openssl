require_relative 'utils'

if defined?(OpenSSL)

class OpenSSL::TestPKeyEC < Test::Unit::TestCase
  def test_read_private_key_der
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ec = OpenSSL::PKey::EC.new(group)
    ec.generate_key
    der = ec.to_der
    ec2 = OpenSSL::PKey.read_private(der)
    assert(ec2.private_key?)
    assert_equal(der, ec2.to_der)
  end

  def test_read_private_key_pem
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ec = OpenSSL::PKey::EC.new(group)
    ec.generate_key
    pem = ec.to_pem
    ec2 = OpenSSL::PKey.read_private(pem)
    assert(ec2.private_key?)
    assert_equal(pem, ec2.to_pem)
  end

  def test_read_public_key_der
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ec = OpenSSL::PKey::EC.new(group)
    ec.generate_key
    ec2 = OpenSSL::PKey::EC.new(group)
    ec2.public_key = ec.public_key
    der = ec2.to_der
    ec3 = OpenSSL::PKey.read_public(der)
    assert(!ec3.private_key?)
    assert_equal(der, ec3.to_der)
  end

  def test_read_public_key_pem
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ec = OpenSSL::PKey::EC.new(group)
    ec.generate_key
    ec2 = OpenSSL::PKey::EC.new(group)
    ec2.public_key = ec.public_key
    pem = ec2.to_pem
    ec3 = OpenSSL::PKey.read_public(pem)
    assert(!ec3.private_key?)
    assert_equal(pem, ec3.to_pem)
  end

  def test_read_private_key_pem_pw
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ec = OpenSSL::PKey::EC.new(group)
    ec.generate_key
    pem = ec.to_pem(OpenSSL::Cipher.new('AES-128-CBC'), 'secret')
    #callback form for password
    ec2 = OpenSSL::PKey.read_private(pem) do
      'secret'
    end
    assert(ec2.private_key?)
    # pass password directly
    ec2 = OpenSSL::PKey.read_private(pem, 'secret')
    assert(ec2.private_key?)
    #omit pem equality check, will be different due to cipher iv
  end

  def test_read_ec_pem_pw
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ec = OpenSSL::PKey::EC.new(group)
    ec.generate_key
    pem = ec.to_pem(OpenSSL::Cipher.new('AES-128-CBC'), 'secret')
    ec2 = OpenSSL::PKey::EC.new(pem, 'secret')
    assert(ec2.private_key?)
    ec3 = OpenSSL::PKey::EC.new(pem) { 'secret' }
    assert(ec3.private_key?)
    assert_equal(ec.to_pem, ec3.to_pem)
  end

  def test_compute_key_block
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key, 128) do |secret, size|
      assert_equal(128, size)
      secret
    end
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key, 128) do |secret, size|
      assert_equal(128, size)
      secret
    end
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_compute_key_default
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key, 128)
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key, 128)
    assert_equal(16, ecdh_secret.bytesize)
    assert_equal(16, ecdh2_secret.bytesize)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def ptest_compute_key_default_size
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key)
    assert_equal(20, ecdh_secret.bytesize) #sha1 20 bytes
    ecdh.dh_compute_key(ecdh2.public_key) do |shared_secret, size|
      assert_equal(20, size)
      shared_secret
    end
  end

  def test_ecdh_default_kdf_static_keys
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    static = OpenSSL::PKey::EC.new(group)
    static.generate_key
    static2 = OpenSSL::PKey::EC.new(group)
    static2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key, 128, static, static2.public_key)
    assert_equal(16, ecdh_secret.bytesize) #sha1 20 bytes
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key, 128, static2, static.public_key)
    assert_equal(16, ecdh2_secret.bytesize)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_ecdh_default_kdf_static_keys_block
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    static = OpenSSL::PKey::EC.new(group)
    static.generate_key
    static2 = OpenSSL::PKey::EC.new(group)
    static2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key, 128, static, static2.public_key) do |secret, size|
      assert_equal(128, size)
      secret
    end
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key, 128, static2, static.public_key) do |secret, size|
      assert_equal(128, size)
      secret
    end
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_ecdh_default_large_size
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key, 2048)
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key, 2048)
    assert_equal(256, ecdh_secret.bytesize)
    assert_equal(256, ecdh2_secret.bytesize)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_ecdh_kdf_ansi_x963_sha1
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key, 128)
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key,
                   128,
                   &OpenSSL::PKey::KeyDerivation.ansi_x963(OpenSSL::Digest::SHA1.new))
    assert_equal(16, ecdh_secret.bytesize)
    assert_equal(16, ecdh2_secret.bytesize)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_ecdh_kdf_ecc_cms_shared_info_sha_256
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key,
                  128,
                  &OpenSSL::PKey::KeyDerivation.ecc_cms_shared_info("2.16.840.1.101.3.4.1.5", OpenSSL::Digest::SHA1.new))
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key,
                  128,
                  &OpenSSL::PKey::KeyDerivation.ecc_cms_shared_info("2.16.840.1.101.3.4.1.5", OpenSSL::Digest::SHA1.new))
    assert_equal(16, ecdh_secret.bytesize)
    assert_equal(16, ecdh2_secret.bytesize)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_ecdh_kdf_nist_800_56a_concatenation_sha_256
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    ecdh_secret = ecdh.dh_compute_key(ecdh2.public_key,
                  128,
                  &OpenSSL::PKey::KeyDerivation.nist_800_56a_concatenation(OpenSSL::Digest::SHA1.new, 'otherinfo'))
    ecdh2_secret = ecdh2.dh_compute_key(ecdh.public_key,
                  128,
                  &OpenSSL::PKey::KeyDerivation.nist_800_56a_concatenation(OpenSSL::Digest::SHA1.new, 'otherinfo'))
    assert_equal(16, ecdh_secret.bytesize)
    assert_equal(16, ecdh2_secret.bytesize)
    assert_equal(ecdh_secret, ecdh2_secret)
  end

  def test_static_priv_needs_public
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    ecdh = OpenSSL::PKey::EC.new(group)
    ecdh.generate_key
    ecdh2 = OpenSSL::PKey::EC.new(group)
    ecdh2.generate_key
    static = OpenSSL::PKey::EC.new(group)
    static.generate_key
    static2 = OpenSSL::PKey::EC.new(group)
    static2.generate_key
    assert_raise(ArgumentError) do
      ecdh.dh_compute_key(ecdh2.public_key, 128, static, nil)
    end
  end

end

end
