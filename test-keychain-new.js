"use strict";

let expect = require('expect.js');
const Keychain = require('./keychain');

function expectReject(fn) {
    try {
        fn();
        expect().fail("Expected failure, but function did not throw");
    } catch (error) {
        // Success: function threw an error as expected
    }
}

describe('Password manager', function() {
    this.timeout(5000);
    let password = "password123!";

    let kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', function() {

        it('inits without an error', function() {
            Keychain.new(password);
        });

        it('can set and retrieve a password', function() {
            let keychain = Keychain.new(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            keychain.set(url, pw);
            expect(keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', function() {
            let keychain = Keychain.new(password);
            for (let k in kvs) {
                keychain.set(k, kvs[k]);
            }
            for (let k in kvs) {
                expect(keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('returns null for non-existent passwords', function() {
            let keychain = Keychain.new(password);
            expect(keychain.get('www.stanford.edu')).to.be(null);
        });

        it('can remove a password', function() {
            let keychain = Keychain.new(password);
            for (let k in kvs) {
                keychain.set(k, kvs[k]);
            }
            expect(keychain.remove('service1')).to.be(true);
            expect(keychain.get('service1')).to.be(null);
        });

        it('returns false if there is no password for the domain being removed', function() {
            let keychain = Keychain.new(password);
            expect(keychain.remove('www.stanford.edu')).to.be(false);
        });

        it('can dump and restore the database', function() {
            let keychain = Keychain.new(password);
            for (let k in kvs) {
                keychain.set(k, kvs[k]);
            }
            let [contents, checksum] = keychain.dump();
            let newKeychain = Keychain.load(password, contents, checksum);
            
            expect(() => JSON.parse(contents)).not.to.throwException();
            for (let k in kvs) {
                expect(newKeychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('fails to restore the database if checksum is wrong', function() {
            let keychain = Keychain.new(password);
            for (let k in kvs) {
                keychain.set(k, kvs[k]);
            }
            let [contents, _] = keychain.dump();
            let fakeChecksum = '3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=';
            expectReject(() => Keychain.load(password, contents, fakeChecksum));
        });

        it('returns false if trying to load with an incorrect password', function() {
            let keychain = Keychain.new(password);
            for (let k in kvs) {
                keychain.set(k, kvs[k]);
            }
            let [contents, checksum] = keychain.dump();
            expectReject(() => Keychain.load("fakepassword", contents, checksum));
        });
    });

    describe('security', function() {

        it("doesn't store domain names and passwords in the clear", function() {
            let keychain = Keychain.new(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            keychain.set(url, pw);
            let [contents, _] = keychain.dump();
            expect(contents).not.to.contain(url);
            expect(contents).not.to.contain(pw);
        });

        it('includes a kvs object in the serialized dump', function() {
            let keychain = Keychain.new(password);
            for (let i = 0; i < 10; i++) {
                keychain.set(String(i), String(i));
            }
            let [contents, _] = keychain.dump();
            let contentsObj = JSON.parse(contents);
            expect(contentsObj).to.have.key('kvs');
            expect(contentsObj.kvs).to.be.an('object');
            expect(Object.keys(contentsObj.kvs)).to.have.length(10);
        });
    });
});
