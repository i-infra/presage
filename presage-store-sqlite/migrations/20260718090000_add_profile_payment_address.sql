-- Decrypted, protobuf-encoded PaymentAddress bytes from the profile.
ALTER TABLE profiles ADD COLUMN payment_address BLOB;
