import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
    credentials: {
        accessKeyId: process.env.AWS_USER_ACCESS_KEY,
        secretAccessKey: process.env.AWS_USER_SECRET_KEY,
    },
    region: process.env.AWS_BUCKET_REGION
});

export const putImage = async (imageName, buffer, mimetype) => {
    const putc = new PutObjectCommand({
        Bucket: process.env.AWS_BUCKET_NAME,
        Key: imageName,
        Body: buffer,
        ContentType: mimetype
    });
    await s3.send(putc);
    const imageURL = `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_BUCKET_REGION}.amazonaws.com/${imageName}`;
    return { imageName, imageURL };
};

export const deleteImage = async (imageName) => {
    const deletec = new DeleteObjectCommand({
        Bucket: process.env.AWS_BUCKET_NAME,
        Key: imageName,
    });
    await s3.send(deletec);
}