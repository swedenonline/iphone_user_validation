//
//  CustomUserInfo.m
//
//  Created by Baloch on 2015-02-26.
//
//

#import <Foundation/Foundation.h>
#import "LinphoneCoreSettingsStore.h"
#import "MD5Library.h"


@implementation CustomUserInfo


- (BOOL) validateUserAccount: username : accountPassword {
    
    if(!username || [username length] == 0) username = [self getUserId];
    
    
    if(!accountPassword || [accountPassword length] == 0)  accountPassword = [self getUserPassword];
    
    
    if(!username || [username length] == 0 || !accountPassword || [accountPassword length] == 0) {
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                        message:NSLocalizedString(@"Mobile number or Password can't be empty.",nil)
                                                       delegate:nil
                                              cancelButtonTitle:@"OK"
                                              otherButtonTitles: nil];
        [alert show];
        [alert release];
        
        return false;
        
    }
    
    NSString *phoneRegex = @"^+46[0-9]{9}$";
    NSPredicate *test = [NSPredicate predicateWithFormat:@"SELF MATCHES %@", phoneRegex];
    if(![test evaluateWithObject:username]) {
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                        message:NSLocalizedString(@"Enter valid Mobile Number e.g. +46xxxxxxxxx.\n",nil)
                                                       delegate:nil
                                              cancelButtonTitle:@"OK"
                                              otherButtonTitles: nil,nil];
        [alert show];
        [alert release];
        return false;
    }
    
    // Don't save data if account already exists with same info
    
    if([[self getUserId] length] == 0 && [[self getUserPassword] length] == 0) { /*do nothing...*/ }
    else {
        if ([username isEqualToString:[CustomUserInfo getUserId]] && [accountPassword isEqualToString:[CustomUserInfo getUserPassword]]) {
            UIAlertView* errorView = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                                message:NSLocalizedString(@"Already saved",nil)
                                                               delegate:nil
                                                      cancelButtonTitle:NSLocalizedString(@"Continue",nil)
                                                      otherButtonTitles:nil,nil];
            [errorView show];
            [errorView release];
            
            return false;
        }
    }
    
    BOOL flag                           = false;
    NSString * challenge                = [self getRandomString];
    NSString * appendKeywithPassword    = [challenge stringByAppendingString:accountPassword];
    NSString * localHashString          = [self generateMD5:appendKeywithPassword];
    NSString* domainName                = @"someurl/auth.php?usr=%@&cm=%@";
    NSString* stringURL                 = [NSString stringWithFormat:domainName,username,challenge];
    NSURL* url                          = [NSURL URLWithString:stringURL];
    
    if(_is_network_reachable()) {
        
        
        NSURLRequest *request           = [NSURLRequest requestWithURL:url
                                               cachePolicy:NSURLRequestReloadRevalidatingCacheData
                                                                            timeoutInterval:30.0];
        NSError * error                 = nil;
        NSURLResponse * response        = nil;
        NSData * data                   = [NSURLConnection sendSynchronousRequest:request
                                                                returningResponse:&response
                                                                            error:&error];
        NSInteger httpCode              = [(NSHTTPURLResponse *)response statusCode];
        
        if (httpCode == 200 || httpCode == 201) {
            NSString * serverHashString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            
            if([[localHashString lowercaseString] isEqualToString:[serverHashString lowercaseString]]) {
                flag = true;
            }
            else {
                UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                                message:NSLocalizedString(@"Incorrect password",nil)
                                                               delegate:nil
                                                      cancelButtonTitle:@"Ok"
                                                      otherButtonTitles: nil];
                [alert show];
                [alert release];
                flag = false;
            }
            
        } else if (httpCode == 400) {
            //Bad Request: Errmsg in response, e.g. "invalid phone number.
            
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                            message:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                                           delegate:nil
                                                  cancelButtonTitle:@"Ok"
                                                  otherButtonTitles: nil];
            [alert show];
            [alert release];
            
            flag = false;
            
        } else if (httpCode == 403) {
            //Forbidden: Account exists but is disabled.
            
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                            message:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                                           delegate:nil
                                                  cancelButtonTitle:@"Ok"
                                                  otherButtonTitles: nil];
            [alert show];
            [alert release];
            
            flag = false;
            
        } else if (httpCode == 404) {
            //Not found: Account doesn't exists.
            
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                            message:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                                           delegate:nil
                                                  cancelButtonTitle:@"Ok"
                                                  otherButtonTitles: nil];
            [alert show];
            [alert release];
            
            flag = false;
            
        } else if (httpCode == 500) {
            //Internal server error
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"",nil)
                                                            message:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                                           delegate:nil
                                                  cancelButtonTitle:@"Ok"
                                                  otherButtonTitles: nil];
            [alert show];
            [alert release];
            flag = false;
            
        } else {
            //Accessing for non-allowable networks
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Unable to connect",nil)
                                                            message:NSLocalizedString(@"",nil)
                                                           delegate:nil
                                                  cancelButtonTitle:@"Ok"
                                                  otherButtonTitles: nil];
            [alert show];
            [alert release];
            flag = false;
            
        }
        
        
    }else {
        // open an alert with just an OK button
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Unable to connect",nil)
                                                        message:NSLocalizedString(@"Please check your internet connection",nil)
                                                       delegate:nil
                                              cancelButtonTitle:@"Ok"
                                              otherButtonTitles: nil];
        [alert show];
        [alert release];
        flag = false;
    }
   
    return flag;
}

- (BOOL) hasUserId {
    NSString *userId = [self getUserId];
    if ([userId isEqualToString:@""] || [userId isEqualToString:nil]) {
        return false;
    }
    else return true;
}

- (BOOL) hasUserPassword {
    NSString *password = [self getUserPassword];
    if ([password isEqualToString:@""] || [password isEqualToString:nil]) {
        return false;
    }
    else return true;
}

- (NSString *) getUserId {
    NSDictionary* ns = [LinphoneCoreSettingsStore getDict];
    NSString *username = [ns objectForKey:@"username_preference"];
    
    if ([username hasPrefix:@"+"] && [username length] > 1) {
        username = [username substringFromIndex:1];
    }
    return username;
}


- (NSString *) getUserPassword {
    NSDictionary* ns = [LinphoneCoreSettingsStore getDict];
    NSString *password = [ns objectForKey:@"password_preference"];
    return password;
}


- (NSString *) getRandomString {
    NSString * randString = [MD5Library randomStringWithLength:32];
    return randString;
}


- (NSString *) generateMD5 : (NSString *) appendedString {
    NSString * hashString = [MD5Library generateMD5:appendedString];
    return hashString;
}

@end
