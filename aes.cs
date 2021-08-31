        public string Encrypt(string StrMensaje,string StrClave = "1234567890abcdef" )
        {

            byte[] key = System.Text.ASCIIEncoding.ASCII.GetBytes(StrClave);
            byte[] secret = System.Text.ASCIIEncoding.ASCII.GetBytes(StrMensaje); 
            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.PKCS7;
                    cryptor.KeySize = 128;
                    cryptor.BlockSize = 128;
                    byte[] iv = cryptor.IV;
                    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(secret, 0, secret.Length);
                    }
                    byte[] encryptedContent = ms.ToArray();
                    byte[] result = new byte[iv.Length + encryptedContent.Length];
                    System.Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    System.Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);
                    return System.Convert.ToBase64String(result);
                }
            }
        }

        public string Decrypt( string StrMensaje, string StrClave= "1234567890abcdef")
        {
            byte[] key = System.Text.ASCIIEncoding.ASCII.GetBytes(StrClave);
            byte[] secret = System.Convert.FromBase64String(StrMensaje);


            byte[] iv = new byte[16]; //initial vector is 16 bytes
            byte[] encryptedContent = new byte[secret.Length - 16]; //lo demás es lo cifrado
            System.Buffer.BlockCopy(secret, 0, iv, 0, iv.Length);
            System.Buffer.BlockCopy(secret, iv.Length, encryptedContent, 0, encryptedContent.Length);
            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.PKCS7;
                    cryptor.KeySize = 128;
                    cryptor.BlockSize = 128;
                    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateDecryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedContent, 0, encryptedContent.Length);
                    }
                    return System.Text.ASCIIEncoding.ASCII.GetString(ms.ToArray());
                }
            }
        }
