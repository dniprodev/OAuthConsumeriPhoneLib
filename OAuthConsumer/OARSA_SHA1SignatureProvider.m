#import "OARSA_SHA1SignatureProvider.h"

#import <Base64/MF_Base64Additions.h>

#import <openssl/rsa.h>
#import <openssl/sha.h>
#import <openssl/pem.h>
#import <openssl/objects.h>
#import <openssl/err.h>

@implementation OARSA_SHA1SignatureProvider

- (NSString *)name 
{
    return @"RSA-SHA1";
}

- (NSString *)signClearText:(NSString *)text withSecret:(NSString *)secretFilePath
{
   FILE *secretFile = fopen([secretFilePath cStringUsingEncoding: NSUTF8StringEncoding], "r");
   NSData *clearTextData = [text dataUsingEncoding: NSUTF8StringEncoding];
   
   SHA_CTX sha_ctx = { 0 };
   unsigned char digest[SHA_DIGEST_LENGTH];
   
   SHA1_Init(&sha_ctx);   
   SHA1_Update(&sha_ctx, [clearTextData bytes], [clearTextData length]);
   SHA1_Final(digest, &sha_ctx);
   
   unsigned char encryptedData[128];
   RSA *rsa = PEM_read_RSAPrivateKey(secretFile, NULL, NULL, NULL);
   if ( rsa == NULL )
   {
      // use openssl errstr #err_number#
      ERR_print_errors_fp(stderr);
      return @"";
   }
   
   unsigned int encryptionLength = 128; //RSA_size(rsa);
   
   RSA_sign(NID_sha1, digest, sizeof digest, encryptedData, &encryptionLength, rsa);
   
//   NSMutableString* stringResult = [NSMutableString stringWithCapacity: 128];
//   for(int i = 0; i < 128; i++)
//      [stringResult appendFormat:@"%02x", encryptedData[i]];
//   NSString* result = [[stringResult dataUsingEncoding: NSUTF8StringEncoding] base64String];
   
   NSData *theData = [NSData dataWithBytes:encryptedData length:encryptionLength];
   NSString *base64EncodedResult = [ theData base64String ];
   
   if (NULL != rsa)
   {
      RSA_free(rsa);
   }

   if (NULL != encryptedData)
   {
      free(encryptedData);
   }
   
   return [base64EncodedResult autorelease];
}

@end
