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

end

end
