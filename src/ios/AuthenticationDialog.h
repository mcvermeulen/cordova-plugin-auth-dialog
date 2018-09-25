/*
 * Copyright (c) Microsoft Open Technologies, Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
 */

#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface AuthenticationDialog: CDVPlugin <NSURLSessionDelegate>

@property NSString *uri;
@property NSString *userName;
@property NSString *password;
@property Boolean allowBypassAuth;


@property NSString *callbackId;


- (void)authenticate:(CDVInvokedUrlCommand*)command;
- (void)clearCredentials:(CDVInvokedUrlCommand*)command;

@end

NSURLSessionTask * _task;
NSString * _host;
NSURLCredentialPersistence _wantedPersistence;
NSURLCredential * _storedCredentials;
BOOL _explicitPersistCredentials;
BOOL _allowUsernameChange;
