//
//  ViewController.swift
//  KnockKnock
//
//  Created by Col Harris on 05/07/2016.
//  Copyright © 2016 Amazon. All rights reserved.
//

import UIKit
import AWSIoT

class ViewController: UIViewController {
    
    var mqttStatus: String = "Disconnected"
    var topic: String = "door"
 
    @IBOutlet weak var activityIndicatorView: UIActivityIndicatorView!
    @IBOutlet weak var logTextView: UITextView!
    @IBOutlet weak var openDoorButton: UIButton!
    
    var connected = false;
    
    var iotDataManager: AWSIoTDataManager!;
    var iotData: AWSIoTData!
    var iotManager: AWSIoTManager!;
    var iot: AWSIoT!
    
    @IBAction func connectButtonPressed(sender: UIButton) {
        
        sender.enabled = false
        
        func mqttEventCallback( status: AWSIoTMQTTStatus )
        {
            dispatch_async( dispatch_get_main_queue()) {
                print("connection status = \(status.rawValue)")
                switch(status)
                {
                case .Connecting:
                    self.mqttStatus = "Connecting..."
                    print( self.mqttStatus )
                    self.logTextView.text = self.mqttStatus
                    
                case .Connected:
                    self.mqttStatus = "Connected"
                    print( self.mqttStatus )
                    sender.setTitle( "Disconnect", forState:.Normal)
                    self.activityIndicatorView.stopAnimating()
                    self.connected = true
                    sender.enabled = true
                    let uuid = NSUUID().UUIDString;
                    let defaults = NSUserDefaults.standardUserDefaults()
                    let certificateId = defaults.stringForKey( "certificateId")
                    self.openDoorButton.enabled = true
                    self.logTextView.text = "Using certificate:\n\(certificateId!)\n\n\nClient ID:\n\(uuid)"
                    
                case .Disconnected:
                    self.mqttStatus = "Disconnected"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView.text = nil
                    
                case .ConnectionRefused:
                    self.mqttStatus = "Connection Refused"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView.text = self.mqttStatus
                    
                case .ConnectionError:
                    self.mqttStatus = "Connection Error"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView.text = self.mqttStatus
                    
                case .ProtocolError:
                    self.mqttStatus = "Protocol Error"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView.text = self.mqttStatus
                    
                default:
                    self.mqttStatus = "Unknown State"
                    print("unknown state: \(status.rawValue)")
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView.text = self.mqttStatus
                    
                }
                NSNotificationCenter.defaultCenter().postNotificationName( "connectionStatusChanged", object: self )
            }
            
        }
        
        if (connected == false)
        {
            activityIndicatorView.startAnimating()
            
            let defaults = NSUserDefaults.standardUserDefaults()
            var certificateId = defaults.stringForKey( "certificateId")
            
            if (certificateId == nil)
            {
                dispatch_async( dispatch_get_main_queue()) {
                    self.logTextView.text = "No identity available, searching bundle..."
                }
                //
                // No certificate ID has been stored in the user defaults; check to see if any .p12 files
                // exist in the bundle.
                //
                let myBundle = NSBundle.mainBundle()
                let myImages = myBundle.pathsForResourcesOfType("p12" as String, inDirectory:nil)
                let uuid = NSUUID().UUIDString;
                
                if (myImages.count > 0) {
                    //
                    // At least one PKCS12 file exists in the bundle.  Attempt to load the first one
                    // into the keychain (the others are ignored), and set the certificate ID in the
                    // user defaults as the filename.  If the PKCS12 file requires a passphrase,
                    // you'll need to provide that here; this code is written to expect that the
                    // PKCS12 file will not have a passphrase.
                    //
                    if let data = NSData(contentsOfFile:myImages[0]) {
                        dispatch_async( dispatch_get_main_queue()) {
                            self.logTextView.text = "found identity \(myImages[0]), importing..."
                        }
                        if AWSIoTManager.importIdentityFromPKCS12Data( data, passPhrase:"", certificateId:myImages[0]) {
                            //
                            // Set the certificate ID and ARN values to indicate that we have imported
                            // our identity from the PKCS12 file in the bundle.
                            //
                            defaults.setObject(myImages[0], forKey:"certificateId")
                            defaults.setObject("from-bundle", forKey:"certificateArn")
                            dispatch_async( dispatch_get_main_queue()) {
                                self.logTextView.text = "Using certificate: \(myImages[0]))"
                                self.iotDataManager.connectWithClientId( uuid, cleanSession:true, certificateId:myImages[0], statusCallback: mqttEventCallback)
                            }
                        }
                    }
                }
                certificateId = defaults.stringForKey( "certificateId")
                if (certificateId == nil) {
                    dispatch_async( dispatch_get_main_queue()) {
                        self.logTextView.text = "No identity found in bundle, creating one..."
                    }
                    //
                    // Now create and store the certificate ID in NSUserDefaults
                    //
                    let csrDictionary = [ "commonName":CertificateSigningRequestCommonName, "countryName":CertificateSigningRequestCountryName, "organizationName":CertificateSigningRequestOrganizationName, "organizationalUnitName":CertificateSigningRequestOrganizationalUnitName ]
                    
                    self.iotManager.createKeysAndCertificateFromCsr(csrDictionary, callback: {  (response ) -> Void in
                        if (response != nil)
                        {
                            defaults.setObject(response.certificateId, forKey:"certificateId")
                            defaults.setObject(response.certificateArn, forKey:"certificateArn")
                            certificateId = response.certificateId
                            print("response: [\(response)]")
                            
                            let attachPrincipalPolicyRequest = AWSIoTAttachPrincipalPolicyRequest()
                            attachPrincipalPolicyRequest.policyName = PolicyName
                            attachPrincipalPolicyRequest.principal = response.certificateArn
                            //
                            // Attach the policy to the certificate
                            //
                            self.iot.attachPrincipalPolicy(attachPrincipalPolicyRequest).continueWithBlock { (task) -> AnyObject? in
                                if let error = task.error {
                                    print("failed: [\(error)]")
                                }
                                if let exception = task.exception {
                                    print("failed: [\(exception)]")
                                }
                                print("result: [\(task.result)]")
                                //
                                // Connect to the AWS IoT platform
                                //
                                if (task.exception == nil && task.error == nil)
                                {
                                    let delayTime = dispatch_time( DISPATCH_TIME_NOW, Int64(2*Double(NSEC_PER_SEC)))
                                    dispatch_after( delayTime, dispatch_get_main_queue()) {
                                        self.logTextView.text = "Using certificate: \(certificateId!)"
                                        self.iotDataManager.connectWithClientId( uuid, cleanSession:true, certificateId:certificateId, statusCallback: mqttEventCallback)
                                    }
                                }
                                return nil
                            }
                        }
                        else
                        {
                            dispatch_async( dispatch_get_main_queue()) {
                                sender.enabled = true
                                self.activityIndicatorView.stopAnimating()
                                self.logTextView.text = "Unable to create keys and/or certificate, check values in Constants.swift"
                            }
                        }
                    } )
                }
            }
            else
            {
                let uuid = NSUUID().UUIDString;
                
                //
                // Connect to the AWS IoT service
                //
                iotDataManager.connectWithClientId( uuid, cleanSession:true, certificateId:certificateId, statusCallback: mqttEventCallback)
            }
        }
        else
        {
            activityIndicatorView.startAnimating()
            logTextView.text = "Disconnecting..."
            
            dispatch_async( dispatch_get_global_queue(Int(QOS_CLASS_USER_INITIATED.rawValue), 0) ){
                self.iotDataManager.disconnect();
                dispatch_async( dispatch_get_main_queue() ) {
                    self.activityIndicatorView.stopAnimating()
                    self.connected = false
                    sender.setTitle( "Connect", forState:.Normal)
                    sender.enabled = true
                }
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        logTextView.resignFirstResponder()
        
        // Init IOT
        //
        // Set up Cognito
        //
        let credentialsProvider = AWSCognitoCredentialsProvider(regionType: AwsRegion, identityPoolId: CognitoIdentityPoolId)
        let configuration = AWSServiceConfiguration(region: AwsRegion, credentialsProvider: credentialsProvider)
        
        AWSServiceManager.defaultServiceManager().defaultServiceConfiguration = configuration
        
        iotManager = AWSIoTManager.defaultIoTManager()
        iot = AWSIoT.defaultIoT()
        
        iotDataManager = AWSIoTDataManager.defaultIoTDataManager()
        iotData = AWSIoTData.defaultIoTData()
        
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    @IBOutlet weak var publishSlider: UISlider!
    
    @IBAction func openDoorClicked(sender: UIButton) {
        print("openDoorClicked")
        
        let iotDataManager = AWSIoTDataManager.defaultIoTDataManager()
        
        //        iotDataManager.publishString("\(sender.value)", onTopic:tabBarViewController.topic, qoS:.MessageDeliveryAttemptedAtMostOnce)
        var jsonData: NSData = NSData()
        
        let para:NSMutableDictionary = NSMutableDictionary()
        para.setValue("open", forKey: "event")
        
        do {
            jsonData = try NSJSONSerialization.dataWithJSONObject(para, options: NSJSONWritingOptions())
        } catch _ {
            
        }
        
        iotDataManager.publishData(jsonData, onTopic:topic, qoS:.MessageDeliveryAttemptedAtMostOnce)
    }
    
}