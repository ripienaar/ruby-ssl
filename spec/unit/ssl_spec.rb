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
        decrypted = @ssl.aes_decrypt(crypted[:key], crypted[:iv], crypted[:data])

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
        @ssl.decrypt_with_private(@ssl.crypt_with_public("foo")).should == "foo"
    end

    it "using a helper it should be able to decrypt with public key what it encrypted using the private key" do
        @ssl.decrypt_with_public(@ssl.crypt_with_private("foo")).should == "foo"
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
        it "should create a key, iv and data" do
            crypted = @ssl.aes_encrypt("foo")

            crypted.include?(:key).should == true
            crypted.include?(:iv).should == true
            crypted.include?(:data).should == true
        end
    end

    describe "#aes_decrypt" do
        it "should decrypted correctly given key, iv and data" do
            key = @ssl.base64_decode("vguhtzSXI16NNb2wrS6S50Y2NjqfV4ZynqYIXTtT064=")
            iv = @ssl.base64_decode("NP6ijoDxy6pQ0TGAO+uL5A==")
            data = @ssl.base64_decode("b6RIfR4GYl20BkHO2XzreA==")

            @ssl.aes_decrypt(key, iv, data).should == "foo"
        end
    end

    describe "#decrypt_with_public" do
        it "should decrypt correctly given key, iv and data in base64 format" do
            crypted = {:key  => "crd4NHvG3A3acSLe9xUU14Lg0wy/cfhCsTsTN92yvjPqbSu5IQbGa5tz5/Ey\nLrw5pfcyLyb3RBKutsgieNhFxVlmMrgsrJV6OcIVuTTDTgK/Kg2Ig/u2FAau\naT2Vwyqi9ahwAPTy9858lcvoA1XSfdmI+roD3Y2L0F6YJGrK8qk=",
                       :iv   => "Ny2BPOPjw6y08+9wB3hQY8ym2xdVoTkcg2RHENbFVjX4DuORkwtVw4iLH59x\ncsaOQi+sLzrA90ncOXYEp+4iP26wdYgUbC7RqVvE9WxBPBuwvdIgZBpH07Oj\nNzYjBrLPROsYfGQkAx382WNGhqsGiLv7xfq508N0p/5LiR1oqE4=",
                       :data => "XWXlqN+i0uHTshzDEFQQqQ=="}

            @ssl.decrypt_with_public(crypted).should == "foo"
        end
    end

    describe "#decrypt_with_private" do
        it "should decrypt correctly given key, iv and data in base64 format" do
            crypted = {:key  => "m5dYEwqoOe1CTTSd3bNjtjYazS8jp97MrwG3t8OqY34c5wCHQ0ugDixGHwVP\nFQJHOWX/uXxbCnAqePTN2skHVYY5YNBo1oKxGy6s+GbNA59QDRT/1zzBphkU\nIoKnAHCjl3LQd8rW+rzavvgUlnuI6N6v4fqHoDYkav2/1UFa+Zg=",
                       :iv   => "jV0NpLdctTuxvCFd8NdcHo4wyeGMA0Axuc1qOkycmrHHpIS6N77YG8XeXly7\nI9yxKZBFMAsU1bVJaNZSo/rpxASdRj19DMK5jdVqO1I3txyRXhe8VyiMXA/i\n+WzX6Tqtnb7jF3vjSvnQ4SDd/b9WqgmKV2+BBB5dgJYLpLhBRHg=",
                       :data => "RDidRVhJaxbib1aVLkT+Mg=="}

            @ssl.decrypt_with_private(crypted).should == "foo"
        end
    end
end
