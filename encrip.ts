import * as crypto from 'crypto';
import * as fs from 'fs';

export class FileEncryptionUseCase {
    // LEER LLAVE PUBLICA
    private RSA_PUBLIC_KEY = fs.readFileSync('./secrets/rsa_public_mlls.pem', 'utf-8');
    async execute(file: Express.Multer.File): Promise<string> {
        try {
            // Obtener la extensión y el buffer del archivo
            const fileExtension = `.${file.originalname.split('.').pop()}`;
            const fileBuffer = file.buffer;

            // Convertir la longitud de la extensión a 4 bytes
            const extensionLengthBuffer = Buffer.alloc(4);
            extensionLengthBuffer.writeUInt32BE(fileExtension.length, 0);

            //Convertir la extensión a bytes
            const extensionBuffer = Buffer.from(fileExtension, 'utf-8');

            //Generar clave y IV para AES
            const aesKey = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);

            //Cifrar el archivo con AES
            const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
            const encryptedFile = Buffer.concat([
                cipher.update(fileBuffer),
                cipher.final(),
            ]);

            //Combinar extensión, IV y archivo cifrado
            const finalEncryptedFile = Buffer.concat([
                extensionLengthBuffer,
                extensionBuffer,
                iv,
                encryptedFile,
            ]);

            //Cifrar la clave AES con RSA
            const encryptedAesKey = crypto.publicEncrypt(
                {
                    key: this.RSA_PUBLIC_KEY,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                },
                aesKey,
            );

            // Guardar archivos
            const encryptedFilePath = `./tmp/${file.originalname}.enc`;
            fs.writeFileSync(encryptedFilePath, finalEncryptedFile);
            const keyFilePath = `./tmp/${file.originalname}.key`;
            fs.writeFileSync(keyFilePath, encryptedAesKey);
            return encryptedFilePath;
        } catch (error) {
            console.error('❌ Error al cifrar el archivo:', error);
            throw new Error('Fallo en el cifrado del archivo');
        }
    }
}