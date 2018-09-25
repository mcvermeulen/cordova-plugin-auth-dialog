/*
 * Copyright (c) Microsoft Open Technologies, Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
 */

#import "AuthenticationDialog.h"

@implementation AuthenticationDialog {}

- (void)authenticate:(CDVInvokedUrlCommand*)command
{
    _explicitPersistCredentials = false;
    _allowUsernameChange = false;
    _wantedPersistence =  NSURLCredentialPersistencePermanent;
    
    self.uri = [command.arguments objectAtIndex:0];
    self.userName = [command.arguments objectAtIndex:1];
    self.password = [command.arguments objectAtIndex:2];
    self.allowBypassAuth = [[command.arguments objectAtIndex:3] boolValue];
    _host = [NSURL URLWithString:self.uri].host;
    
    self.callbackId = command.callbackId;
    
    NSLog(@"AuthDialog: authenticate %@", self.uri);
    
    [self credentialStorage:NO];
    
    // large timout is used so that we have enough time to request user name and password
    NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:self.uri]
                                                           cachePolicy:NSURLRequestUseProtocolCachePolicy
                                                       timeoutInterval:60000.0];
    
    // use HEAD since it is faster than actial data retrieving (GET)
    // this does not work due to WebView issue: http://stackoverflow.com/questions/25755555/stream-is-sending-an-event-before-being-opened
    [request setHTTPMethod:@"HEAD"];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]
                                                          delegate:self
                                                     delegateQueue:[NSOperationQueue mainQueue]];
     _task = [session dataTaskWithRequest:request];
     [_task resume];
}


- (void)URLSession:(NSURLSession *)session
        dataTask:(NSURLSessionDataTask *)dataTask
        didReceiveResponse:(NSURLResponse *)response
        completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler {
    CDVPluginResult* pluginResult;
    
    NSInteger statusCode = [((NSHTTPURLResponse *)response) statusCode];
    NSLog(@"Didreceive response %ld", (long)statusCode);
    // 405 means 'Mehod not allowed' which is totally ok to understand
    // we have successfully passed authentication
    if (statusCode == 200 || statusCode == 405) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:
                        [NSHTTPURLResponse localizedStringForStatusCode: statusCode]];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackId];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didCompleteWithError:(nullable NSError *)error {
    NSLog(@"didCompleteWithError %@", error );
    [self clearCredentialsForHost];
    
    CDVPluginResult* errorResult;
    if (error.code == NSURLErrorUserCancelledAuthentication) {
        errorResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"cancelled"];
    } else {
        errorResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[error localizedDescription]];
    }
    
    [self.commandDelegate sendPluginResult:errorResult callbackId:self.callbackId];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler {
      NSLog(@"didRecieveChallenge %@ failure count : %ld", challenge.protectionSpace, (long)challenge.previousFailureCount );

    if (challenge.failureResponse != nil) {
        NSHTTPURLResponse* res = ((NSHTTPURLResponse *)challenge.failureResponse);
        NSLog(@"didRecieveChallenge failure url: %@, statusCode : %ld", challenge.failureResponse.URL, (long)res.statusCode);
    }
    
    if (challenge.previousFailureCount == 1 ) {
        [[challenge sender] continueWithoutCredentialForAuthenticationChallenge:challenge];
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    else {
        // Check if there is already a credential stored explicitly
        NSURLCredential *credential = [self getStoredCredentialsForHost];
        if (credential != nil) {
            NSLog(@"Explicitly setting username/password from storage : %@", credential.user);
            // Send result
            [[challenge sender] useCredential:[NSURLCredential credentialWithUser:credential.user
                                                                         password:credential.password
                                                                      persistence:_wantedPersistence]
                                                        forAuthenticationChallenge:challenge];
            
            completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential
                                                                       credentialWithUser:credential.user
                                                                       password:credential.password
                                                                       persistence:_wantedPersistence]);
        }
        else {
        
            NSLog(@"Ask for credentials %@", challenge );
            UIAlertController * alert= [UIAlertController alertControllerWithTitle:@"Autorisatie vereist"
                                                                           message:@""
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction* ok = [UIAlertAction actionWithTitle:@"Inloggen"
                                                         style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {
                                                           NSArray<UITextField *> *textFields = alert.textFields;
                                                           
                                                           NSString *username = self.userName;
                                                           NSString *password = @"";
                                                           
                                                           if (_allowUsernameChange) {
                                                               username =textFields[0].text;
                                                               password = textFields[1].text;
                                                           } else {
                                                            password = textFields[0].text;
                                                           }
                                                           
                                                           [alert dismissViewControllerAnimated:YES completion:nil];
                                                         
                                                            if (_explicitPersistCredentials) {
                                                               // Store credentials explicitly for the wanted protectionSpace
                                                               NSURLCredential *credential = [NSURLCredential credentialWithUser:username password:password persistence:NSURLCredentialPersistencePermanent];
                                                               
                                                               [[NSURLCredentialStorage sharedCredentialStorage] setCredential:credential forProtectionSpace:challenge.protectionSpace];
                                                                NSLog(@"Explicitly stored username/password from storage : %@", credential.user);
                                                            }
                                                           // Send result
                                                           [[challenge sender] useCredential:[NSURLCredential credentialWithUser:username
                                                                                                                        password:password
                                                                                                                     persistence:_wantedPersistence]
                                                                                                            forAuthenticationChallenge:challenge];
                                                           
                                                           completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential
                                                                                                                      credentialWithUser:username
                                                                                                                      password:password
                                                                                                            persistence:_wantedPersistence]);
       
                                                       }];
            
            UIAlertAction* cancel = [UIAlertAction actionWithTitle:@"Annuleren"
                                                             style:UIAlertActionStyleDefault
                                                           handler:^(UIAlertAction * action) {
                                                               [alert dismissViewControllerAnimated:YES completion:nil];
                                                               [self clearCredentialsForHost];
                                                                completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
             
                                                           }];
            [alert addAction:cancel];
            [alert addAction:ok];
            
            if (_allowUsernameChange) {
                [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
                    textField.text = self.userName;
                }];
            }
            [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
                textField.placeholder = @"Password";
                textField.secureTextEntry = YES;
            }];
            
             [self.viewController presentViewController:alert animated:YES completion:nil];
        }
    }
}

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler {
    
    NSString *userName =@"";
    NSString *password = @"";
    
    completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialWithUser:userName
                                                                                         password:password
                                                                                      persistence:_wantedPersistence]);
}

-(NSURLCredential* )getStoredCredentialsForHost
{
    if (!_explicitPersistCredentials) {
        _storedCredentials = nil;
        return nil;
    }
    NSLog(@"AuthDialog: fromCredentialStorage for %@", _host);
    if (_storedCredentials == nil)
    {
        NSDictionary* credentialsDict = [[NSURLCredentialStorage sharedCredentialStorage] allCredentials];
        
        for (NSURLProtectionSpace* protectionSpace in credentialsDict){
            NSLog(@"Protection space: %@", protectionSpace );
            if ([protectionSpace.host isEqualToString:_host]) {
                NSDictionary* userNameDict = credentialsDict[protectionSpace];
                for (NSString* userName in userNameDict){
                    NSLog(@"AuthDialog.fromCredentialStorage: credential: %@", userName);
                    _storedCredentials = userNameDict[userName];
                    return _storedCredentials;
                }
            } else {
                NSLog(@"incorrect '%@' and '%@'", _host, protectionSpace.host);
            }
        }
    }
    return _storedCredentials;
}

-(void) clearCredentialsForHost {
   if (!_explicitPersistCredentials) {
       return;
   }
    NSDictionary* credentialsDict = [[NSURLCredentialStorage sharedCredentialStorage] allCredentials];
    
    for (NSURLProtectionSpace* protectionSpace in credentialsDict){
        NSLog(@"Protection space: %@", protectionSpace );
        if ([protectionSpace.host isEqualToString:_host]) {
            NSDictionary* userNameDict = credentialsDict[protectionSpace];
            for (NSString* userName in userNameDict){
                NSLog(@"AuthDialog: credential: remove: %@", userName);
                NSURLCredential* credential = userNameDict[userName];
                [[NSURLCredentialStorage sharedCredentialStorage] removeCredential:credential forProtectionSpace:protectionSpace];
            }
        }
    }
    _storedCredentials = nil;
}


-(void)credentialStorage:(bool)remove
{
    NSLog(@"AuthDialog: credentialStorage");
    
    NSDictionary* credentialsDict = [[NSURLCredentialStorage sharedCredentialStorage] allCredentials];
    
    for (NSURLProtectionSpace* protectionSpace in credentialsDict){
        NSLog(@"protectionSpace : %@", protectionSpace);
        NSDictionary* userNameDict = credentialsDict[protectionSpace];
        for (NSString* userName in userNameDict){
            NSLog(@"AuthDialog: credential: %@", userName);
            
            if (remove == YES) {
                NSLog(@"AuthDialog: credential: remove: %@", userName);
                NSURLCredential* credential = userNameDict[userName];
                [[NSURLCredentialStorage sharedCredentialStorage] removeCredential:credential forProtectionSpace:protectionSpace];
            }
        }
    }
    
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
}

-(void)clearCredentials:(CDVInvokedUrlCommand*) command
{
    NSLog(@"AuthDialog: clearCredentials");
    [self credentialStorage:YES];
    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
}

@end
