//
//  OAMutableURLRequest.m
//  OAuthConsumer
//
//  Created by Jon Crosby on 10/19/07.
//  Copyright 2007 Kaboomerang LLC. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.


#import "OAMutableURLRequest.h"

@interface OAMutableURLRequest ()

- (NSString *)_signatureBaseString;

@end

@implementation OAMutableURLRequest
@synthesize signature, nonce;

#pragma mark init

- (NSString*)generateTimestamp
{
   return [NSString stringWithFormat:@"%ld", time(NULL)];
}

- (NSString*)generateNonce
{
   CFUUIDRef theUUID = CFUUIDCreate(NULL);
   CFStringRef string = CFUUIDCreateString(NULL, theUUID);
   CFRelease(theUUID);
   return [ (NSString *)string autorelease ];
}

// Setting a timestamp and nonce to known
// values can be helpful for testing
- (id)initWithURL:(NSURL *)aUrl
         consumer:(OAConsumer *)aConsumer
            token:(OAToken *)aToken
            realm:(NSString *)aRealm
signatureProvider:(id<OASignatureProviding, NSObject>)aProvider
        timestamp:(NSString *)aTimestamp
            nonce:(NSString *)aNonce
{
	if (self = [super initWithURL:aUrl
                     cachePolicy:NSURLRequestReloadIgnoringCacheData
                 timeoutInterval:10.0])
	{    
		consumer = [aConsumer retain];
		
		// empty token for Unauthorized Request Token transaction
		if (aToken == nil)
			token = [[OAToken alloc] init];
		else
			token = [aToken retain];
		
		if (aRealm == nil)
			realm = [[NSString alloc] initWithString:@""];
		else 
			realm = [aRealm retain];
		
		// default to HMAC-SHA1
		if (aProvider == nil)
			signatureProvider = [[OAHMAC_SHA1SignatureProvider alloc] init];
		else 
			signatureProvider = [aProvider retain];
		
		timestamp = [aTimestamp retain];
		nonce = [aNonce retain];
	}
   return self;
}

- (id)initWithURL:(NSURL *)aUrl
         consumer:(OAConsumer *)aConsumer
            token:(OAToken *)aToken
            realm:(NSString *)aRealm
signatureProvider:(id<OASignatureProviding, NSObject>)aProvider
{
   return [ self initWithURL: aUrl
                    consumer: aConsumer
                       token: aToken
                       realm: aRealm
           signatureProvider: aProvider
                   timestamp: [ self generateTimestamp ]
                       nonce: [ self generateNonce ] ];
}

- (id)initWithURL:(NSURL *)aUrl
         consumer:(OAConsumer *)aConsumer
            token:(OAToken *)aToken
            realm:(NSString *)aRealm
signatureProvider:(id<OASignatureProviding, NSObject>)aProvider
        timestamp:(NSString *)aTimestamp
{
   return [ self initWithURL: aUrl
                    consumer: aConsumer
                       token: aToken
                       realm: aRealm
           signatureProvider: aProvider
                   timestamp: aTimestamp
                       nonce: [ self generateNonce ] ];
}

- (void)dealloc
{
	[consumer release];
	[token release];
	[realm release];
	[signatureProvider release];
	[timestamp release];
	[nonce release];
	[super dealloc];
}

#pragma mark -
#pragma mark Public

- (NSDictionary*)baseAuthHeaderComponents
{
   return @{
   @"OAuth realm"            : [self URLEncodedString: realm],
   @"oauth_consumer_key"     : [self URLEncodedString: consumer.key],
   @"oauth_signature_method" : [self URLEncodedString: [signatureProvider name]],
   @"oauth_timestamp"        : timestamp,
   @"oauth_nonce"            : nonce,
   @"oauth_version"          : @"1.0"
   };
}

- (NSDictionary*)requestRequestTokenAuthHeaderComponents
{
   NSMutableDictionary* components_ = [ NSMutableDictionary dictionaryWithDictionary: [ self baseAuthHeaderComponents ] ];
   [ components_ setObject: [self URLEncodedString: @"http://locallocallocalhots"] forKey: @"oauth_callback" ];
   return components_;
}

- (NSDictionary*)requestAccessTokenAuthHeaderComponents
{
   NSMutableDictionary* components_ = [ NSMutableDictionary dictionaryWithDictionary: [ self baseAuthHeaderComponents ] ];
   [ components_ setObject: [ self URLEncodedString: [ self URLEncodedString:token.key] ] forKey: @"oauth_token" ];
   [ components_ setObject: [ self URLEncodedString: [ self URLEncodedString:token.pin] ] forKey: @"oauth_verifier" ];
   return components_;
}

- (NSDictionary*)apiRequestAuthHeaderComponents
{
   NSMutableDictionary* components_ = [ NSMutableDictionary dictionaryWithDictionary: [ self baseAuthHeaderComponents ] ];
   [ components_ setObject: [ self URLEncodedString: [ self URLEncodedString:token.key ] ] forKey: @"oauth_token" ];
   return components_;
}

- (NSString*)signatureForHeaderComponents:(NSDictionary*)components
{
	NSString *consumerSecret = [self URLEncodedString: consumer.secret];
	NSString	*tokenSecret    = [self URLEncodedString: token.secret];
   
   NSString* secret = nil;
   
   if ( [[signatureProvider name] isEqualToString: @"HMAC-SHA1"] )
   {
      secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret];
   }
   else
   {
      secret = [[NSBundle mainBundle] pathForResource: @"RSA" ofType: @"pem"];
   }
   
   return [signatureProvider signClearText:[self signatureBaseStringWithComponents:components]
                                withSecret:secret];
}

-(NSString*)authorizationParamWithComponents:( NSDictionary* )components_
{
   NSMutableArray* pairs = [NSMutableArray arrayWithCapacity: [[components_ allKeys] count]];
   for (NSString* name in [components_ allKeys])
   {
      [pairs addObject: [NSString stringWithFormat: @"%@=\"%@\"", name, [components_ objectForKey: name]]];
   }

   NSString* signature_ = [self signatureForHeaderComponents: components_];
   [pairs addObject: [NSString stringWithFormat: @"oauth_signature=\"%@\"", [self URLEncodedString:signature_]]];

   NSArray *sortedPairs = [pairs sortedArrayUsingSelector:@selector(compare:)];

   NSString* auth_param_value_ = [sortedPairs componentsJoinedByString: @", "];
   
   NSLog(@"Authorization:\n%@\n============================", auth_param_value_);
   return auth_param_value_;
}

-(void)setAuthHeaderParamValue:( NSString* )auth_value_
{
   [self setValue:auth_value_ forHTTPHeaderField:@"Authorization"];
}

- (void)prepareForRequestToken
{
   NSString* auth_value_ = [self authorizationParamWithComponents: [self requestRequestTokenAuthHeaderComponents]];
   [self setAuthHeaderParamValue: auth_value_ ];
}

- (void)prepareForAccessToken
{
   NSString* auth_value_ = [self authorizationParamWithComponents: [self requestAccessTokenAuthHeaderComponents]];
   [self setAuthHeaderParamValue: auth_value_ ];
}

- (void)prepareForApiRequest
{
   NSString* auth_value_ = [self authorizationParamWithComponents: [self apiRequestAuthHeaderComponents]];
   [self setAuthHeaderParamValue: auth_value_ ];
}

- (void)prepare
{
   // sign
	// Secrets must be urlencoded before concatenated with '&'
	// TODO: if later RSA-SHA1 support is added then a little code redesign is needed
   
	
	NSString					*consumerSecret = [self URLEncodedString: consumer.secret];
	NSString					*tokenSecret = [self URLEncodedString: token.secret];
	

   NSString* secret = nil;

   if ( [[signatureProvider name] isEqualToString: @"HMAC-SHA1"] )
   {
      secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret];
   }
   else
   {
      secret = [[NSBundle mainBundle] pathForResource: @"RSA" ofType: @"pem"];
   }

   signature = [signatureProvider signClearText:[self _signatureBaseString]
                                     withSecret:secret];
   
   // set OAuth headers
   NSString *oauthToken;
   if ([token.key isEqualToString:@""])
      oauthToken = @""; // not used on Request Token transactions
   else
      oauthToken = [NSString stringWithFormat:@"oauth_token=\"%@\", ", [self URLEncodedString: token.key]];
   
   NSString *oauthHeader = [NSString stringWithFormat:
//                            @"OAuth realm=\"%@\", oauth_consumer_key=\"%@\", %@oauth_signature_method=\"%@\", oauth_signature=\"%@\", oauth_timestamp=\"%@\", oauth_nonce=\"%@\", oauth_version=\"1.0\"",
                            @"OAuth realm=\"%@\", oauth_consumer_key=\"%@\", %@oauth_signature_method=\"%@\", oauth_signature=\"%@\", oauth_timestamp=\"%@\", oauth_nonce=\"%@\", oauth_version=\"1.0\", oauth_callback=\"%@\"",
                            [self URLEncodedString: realm],
                            [self URLEncodedString: consumer.key],
                            oauthToken,
                            [self URLEncodedString: [signatureProvider name]],
                            [self URLEncodedString: signature],
                            timestamp,
                            nonce,
                            [self URLEncodedString: @"http://locallocallocalhots"]
                            ];
	
	if (token.pin.length) oauthHeader = [oauthHeader stringByAppendingFormat: @", oauth_verifier=\"%@\"", token.pin];					//added for the Twitter OAuth implementation

   NSLog(@"HEADER:\n%@", oauthHeader);
   [self setValue:oauthHeader forHTTPHeaderField:@"Authorization"];
}

#pragma mark -
#pragma mark Private

- (NSString *)signatureBaseStringWithComponents:( NSDictionary* )components
{
   // OAuth Spec, Section 9.1.1 "Normalize Request Parameters"
   // build a sorted array of both request parameters and OAuth header parameters
   
   NSMutableDictionary* mutableComps = [NSMutableDictionary dictionaryWithDictionary: components];
   for (OARequestParameter *param in [self parameters])
   {
      [mutableComps setObject: [self URLEncodedString:param.value] forKey: [self URLEncodedString:param.name]];
   }
   [mutableComps removeObjectForKey: @"OAuth realm"];

   NSMutableArray* pairs = [NSMutableArray arrayWithCapacity: [[mutableComps allKeys] count]];
   for (NSString* name in [mutableComps allKeys])
   {
      [pairs addObject: [NSString stringWithFormat: @"%@=%@", name, [mutableComps objectForKey: name]]];
   }
   
   NSArray *sortedPairs = [pairs sortedArrayUsingSelector:@selector(compare:)];
   NSString *normalizedRequestParameters = [sortedPairs componentsJoinedByString:@"&"];

   // OAuth Spec, Section 9.1.2 "Concatenate Request Elements"

   NSString *ret = [NSString stringWithFormat:@"%@&%@&%@",
                    [self HTTPMethod],
                    [self URLEncodedString: [self URLStringWithoutQueryFromURL: [self URL]]],
                    [self URLEncodedString: normalizedRequestParameters]];

	NSLog(@"Signature Base String:\n%@", ret);
	return ret;
}

- (NSString *)_signatureBaseString
{
   // OAuth Spec, Section 9.1.1 "Normalize Request Parameters"
   // build a sorted array of both request parameters and OAuth header parameters
   NSMutableArray *parameterPairs = [NSMutableArray  arrayWithCapacity:(8 + [[self parameters] count])]; // 6 being the number of OAuth params in the Signature Base String
   
	[parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_callback" value:@"http://locallocallocalhots"] URLEncodedNameValuePair]];
	[parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_consumer_key" value:consumer.key] URLEncodedNameValuePair]];
	[parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_signature_method" value:[signatureProvider name]] URLEncodedNameValuePair]];
	[parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_timestamp" value:timestamp] URLEncodedNameValuePair]];
	[parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_nonce" value:nonce] URLEncodedNameValuePair]];
	[parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_version" value:@"1.0"] URLEncodedNameValuePair]];
   
   if (token.key.length > 0) [parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_token" value:token.key] URLEncodedNameValuePair]];
   if (token.pin.length > 0) [parameterPairs addObject:[[OARequestParameter requestParameterWithName:@"oauth_verifier" value:token.pin] URLEncodedNameValuePair]];		//added for the Twitter OAuth implementation
   
   for (OARequestParameter *param in [self parameters]) {
      [parameterPairs addObject:[param URLEncodedNameValuePair]];
   }
   
   NSArray *sortedPairs = [parameterPairs sortedArrayUsingSelector:@selector(compare:)];
   NSString *normalizedRequestParameters = [sortedPairs componentsJoinedByString:@"&"];
   
   // OAuth Spec, Section 9.1.2 "Concatenate Request Elements"
   NSString *ret = [NSString stringWithFormat:@"%@&%@&%@",
                    [self HTTPMethod],
                    [self URLEncodedString: [self URLStringWithoutQueryFromURL: [self URL]]],
                    [self URLEncodedString: normalizedRequestParameters]];

	NSLog(@"Signature Base String (orig):\n%@", ret);
	
   return ret;
}

- (NSString *)URLStringWithoutQueryFromURL: (NSURL *) url
{
   NSArray *parts = [[url absoluteString] componentsSeparatedByString:@"?"];
   return [parts objectAtIndex:0];
}



//=============================================================================================================================
#pragma mark Parameters
- (NSArray *)parameters 
{
   NSString *encodedParameters = nil;
   
   if ([[self HTTPMethod] isEqualToString:@"GET"] || [[self HTTPMethod] isEqualToString:@"DELETE"]) 
   {
      encodedParameters = [[self URL] query];
   }
	else 
	{
      encodedParameters = [[NSString alloc] initWithData:[self HTTPBody]
                                                encoding:NSUTF8StringEncoding];
      [ encodedParameters autorelease ];
   }
   
   if ((encodedParameters == nil) || ([encodedParameters isEqualToString:@""]))
   {
      return nil;
   }
   
   NSArray *encodedParameterPairs = [encodedParameters componentsSeparatedByString:@"&"];
   NSMutableArray *requestParameters = [[NSMutableArray alloc] initWithCapacity:16];
   
   for (NSString *encodedPair in encodedParameterPairs) 
	{
      NSArray *encodedPairElements = [encodedPair componentsSeparatedByString:@"="];
      OARequestParameter *parameter = [OARequestParameter requestParameterWithName:[self URLEncodedString: [encodedPairElements objectAtIndex:0]]
                                                                             value:[self URLEncodedString: [encodedPairElements objectAtIndex:1]]];
      [requestParameters addObject:parameter];
   }
	
   return [requestParameters autorelease];
}

- (void)setParameters:(NSArray *)parameters 
{
   NSMutableString *encodedParameterPairs = [NSMutableString stringWithCapacity:256];

   int position = 1;
   for (OARequestParameter *requestParameter in parameters) 
	{
      [encodedParameterPairs appendString:[requestParameter URLEncodedNameValuePair]];
      if (position < [parameters count])
         [encodedParameterPairs appendString:@"&"];
		
      position++;
   }

   if ([[self HTTPMethod] isEqualToString:@"GET"] || [[self HTTPMethod] isEqualToString:@"DELETE"])
      [self setURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@?%@", [self URLStringWithoutQueryFromURL: [self URL]], encodedParameterPairs]]];
   else 
	{
      // POST, PUT
      NSData *postData = [encodedParameterPairs dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
      [self setHTTPBody:postData];
      [self setValue:[NSString stringWithFormat:@"%d", [postData length]] forHTTPHeaderField:@"Content-Length"];
      [self setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
   }
}


- (NSString *) URLEncodedString: (NSString *) string {
   CFStringRef preprocessedString = CFURLCreateStringByReplacingPercentEscapesUsingEncoding(kCFAllocatorDefault, (CFStringRef) string, CFSTR(""), kCFStringEncodingUTF8);
   NSString *result = (NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault,
                                                                          (CFStringRef) string,
                                                                          NULL,
                                                                          CFSTR("!*'();:@&=+$,/?%#[]"),
                                                                          kCFStringEncodingUTF8);
   [result autorelease];
   if ( preprocessedString )
   {
      CFRelease(preprocessedString);
   }
   return result;	
}
@end
