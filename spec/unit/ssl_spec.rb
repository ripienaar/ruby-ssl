#!/usr/bin/env ruby

require File.dirname(__FILE__) + '/../spec_helper'

describe SSL do
    before do
        @rootdir = File.dirname(__FILE__)
        @ssl = SSL.new("#{@rootdir}/../fixtures/test-public.pem", "#{@rootdir}/../fixtures/test-private.pem")
    end

    it "should be able to decode base64 text it encoded" do
        @ssl.base64_decode(@ssl.base64_encode("foo")).should == "foo"
    end

    it "should decrypt what it encrypted with RSA" do
        crypted = @ssl.aes_encrypt("foo")
        decrypted = @ssl.aes_decrypt(crypted[:key], crypted[:data])

        decrypted.should == "foo"
    end

    it "should be able to decrypt using RSA private key what it encrypted with RSA public key" do
        crypted = @ssl.rsa_encrypt_with_public("foo")
        decrypted = @ssl.rsa_decrypt_with_private(crypted)

        decrypted.should == "foo"
    end

    it "should be able to decrypt using RSA public key what it encrypted with RSA private key" do
        crypted = @ssl.rsa_encrypt_with_private("foo")
        decrypted = @ssl.rsa_decrypt_with_public(crypted)

        decrypted.should == "foo"
    end

    it "using a helper it should be able to decrypt with private key what it encrypted using the public key" do
        @ssl.decrypt_with_private(@ssl.encrypt_with_public("foo")).should == "foo"
    end

    it "using a helper it should be able to decrypt with public key what it encrypted using the private key" do
        @ssl.decrypt_with_public(@ssl.crypt_with_private("foo")).should == "foo"
    end

    describe "#initialize" do
        it "should default to aes-256-cbc" do
            @ssl.ssl_cipher.should == "aes-256-cbc"
        end

        it "should set the supplied ssl cipher" do
            @ssl = SSL.new("#{@rootdir}/../fixtures/test-public.pem", "#{@rootdir}/../fixtures/test-private.pem", nil, "aes-128-cbc")
            @ssl.ssl_cipher.should == "aes-128-cbc"
        end

        it "should fail on invalid ciphers" do
            expect {
                @ssl = SSL.new("#{@rootdir}/../fixtures/test-public.pem", "#{@rootdir}/../fixtures/test-private.pem", nil, "foo-foo-foo")
            }.to raise_error("Unknown SSL cipher foo-foo-foo")
        end
    end

    describe "#read_key" do
        it "should fail on non exiting files" do
            expect {
                @ssl.read_key(:public, "/nonexisting")
            }.to raise_error("Could not find key /nonexisting")
        end

        it "should fail on unknown key types" do
            expect {
                @ssl.read_key(:unknown, @ssl.public_key_file)
            }.to raise_error("Can only load :public or :private keys")
        end

        it "should read a public key" do
            @ssl.read_key(:public, "#{@rootdir}/../fixtures/test-public.pem")
        end

        it "should return nil if no key was given" do
            @ssl.read_key(:public).should == nil
        end

        it "should return nil if nil key was given" do
            @ssl.read_key(:public, nil).should == nil
        end
    end

    describe "#random_string" do
        it "should return correct length passwords" do
            @ssl.random_string(30).length.should == 30
        end

        it "should return 20 characters by default" do
            @ssl.random_string.length.should == 20
        end

        it "should always return different strings" do
            @ssl.random_string.should_not == @ssl.random_string
        end
    end

    describe "#base64_encode" do
        it "should correctly encode" do
            @ssl.base64_encode("foo").should == "Zm9v"
        end
    end

    describe "#base64_decode" do
        it "should correctly decode" do
            @ssl.base64_decode("Zm9v").should == "foo"
        end
    end

    describe "#aes_encrypt" do
        it "should create a key and data" do
            crypted = @ssl.aes_encrypt("foo")

            crypted.include?(:key).should == true
            crypted.include?(:data).should == true
        end
    end

    describe "#aes_decrypt" do
        it "should decrypted correctly given key and data" do
            key = @ssl.base64_decode("rAaCyW6qB0XqZNa9hji0qHwrI3P47t8diLNXoemW9ss=")
            data = @ssl.base64_decode("mSthvO/wSl0ArNOcgysTVw==")

            @ssl.aes_decrypt(key, data).should == "foo"
        end

        it "should decrypt correctly given key, data and cipher" do
            key = @ssl.base64_decode("VEma3a/R7fjw2M4d0NIctA==")
            data = @ssl.base64_decode("FkH6qLvKTn7a+uNPe8ciHA==")

            # the default aes-256-cbc should fail here, the key above is 128 bit
            expect { @ssl.aes_decrypt(key, data) }.to raise_error(/key length too short: no start line/)

            # new ssl instance configured for aes-128-cbc, should work
            @ssl = SSL.new("#{@rootdir}/../fixtures/test-public.pem", "#{@rootdir}/../fixtures/test-private.pem", nil, "aes-128-cbc")
            @ssl.aes_decrypt(key, data).should == "foo"
        end
    end

    describe "#decrypt_with_public" do
        it "should decrypt correctly given key and data in base64 format" do
            crypted = {:key=> "YaRcSDdcKgnRZ4Eu2eirl/+lzDgVkPZ41kXAQQNOi+6AfjdbbOW7Zblibx9r\n3TzZAi0ulA94gqNAXPvPC8LaO8W9TtJwlto/RHwDM7ZdfqEImSYoVACFNq28\n+0MLr3K3hIBsB1pyxgFTQul+MrCq+3Fik7Nj7ZKkJUT2veyqbg8=",
                       :data=>"TLVw1EYeOaGDmEC/R2I/cA=="}

            @ssl.decrypt_with_public(crypted).should == "foo"
        end
    end

    describe "#decrypt_with_private" do
        it "should decrypt correctly given key and data in base64 format" do
            crypted = {:key=> "kO1kUgJBiEBdoajN4OHp9BOie6dCznf1YKbBnp3LOyBxcDDQtjxEBlPmjQve\npXrQJ5xpLX6oNBxzU18Pf2SKYUZSbzIkDUb97GQY0WoBQsdM2OwPXH+HtF2A\no5N8iIx9srPAEAFa6hZAdqvcmRT/SzhP1kH+Gyy8fyvW8HGBjNY=",
                       :data=>"gDTaHCmes/Yua4jtjmgukQ=="}

            @ssl.decrypt_with_private(crypted).should == "foo"
        end
    end

    describe "#decrypt_with_private" do
        it "should fail if not given a key" do
            expect {
                @ssl.decrypt_with_private({:iv => "x", :data => "x"})
            }.to raise_error("Crypted data should include a key")
        end

        it "should fail if not given data" do
            expect {
                @ssl.decrypt_with_private({:iv => "x", :key => "x"})
            }.to raise_error("Crypted data should include data")
        end
    end

    describe "#decrypt_with_public" do
        it "should fail if not given a key" do
            expect {
                @ssl.decrypt_with_public({:iv => "x", :data => "x"})
            }.to raise_error("Crypted data should include a key")
        end

        it "should fail if not given data" do
            expect {
                @ssl.decrypt_with_public({:iv => "x", :key => "x"})
            }.to raise_error("Crypted data should include data")
        end
    end
end
