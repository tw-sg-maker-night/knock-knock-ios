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
    @IBOutlet weak var logTextView: UITextView?
    @IBOutlet weak var openDoorButton: UIButton!
    
    var connected = false;
    
    var iotDataManager: AWSIoTDataManager!;
    var iotData: AWSIoTData!
    var iotManager: AWSIoTManager!;
    var iot: AWSIoT!
    
    @IBAction func connectButtonPressed(_ sender: UIButton) {
        
        sender.isEnabled = false
        
        func mqttEventCallback( _ status: AWSIoTMQTTStatus )
        {
            DispatchQueue.main.async {
                print("connection status = \(status.rawValue)")
                switch(status)
                {
                case .connecting:
                    self.mqttStatus = "Connecting..."
                    print( self.mqttStatus )
                    self.logTextView?.text = self.mqttStatus
                    
                case .connected:
                    self.mqttStatus = "Connected"
                    print( self.mqttStatus )
                    sender.setTitle( "Disconnect", for:UIControlState())
                    self.activityIndicatorView.stopAnimating()
                    self.connected = true
                    sender.isEnabled = true
                    let uuid = UUID().uuidString;
                    let defaults = UserDefaults.standard
                    let certificateId = defaults.string( forKey: "certificateId")
                    self.openDoorButton.isEnabled = true
                    self.logTextView?.text = "Using certificate:\n\(certificateId!)\n\n\nClient ID:\n\(uuid)"
                    
                case .disconnected:
                    self.mqttStatus = "Disconnected"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView?.text = nil
                    
                case .connectionRefused:
                    self.mqttStatus = "Connection Refused"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView?.text = self.mqttStatus
                    
                case .connectionError:
                    self.mqttStatus = "Connection Error"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView?.text = self.mqttStatus
                    
                case .protocolError:
                    self.mqttStatus = "Protocol Error"
                    print( self.mqttStatus )
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView?.text = self.mqttStatus
                    
                default:
                    self.mqttStatus = "Unknown State"
                    print("unknown state: \(status.rawValue)")
                    self.activityIndicatorView.stopAnimating()
                    self.logTextView?.text = self.mqttStatus
                    
                }
                NotificationCenter.default.post( name: Notification.Name(rawValue: "connectionStatusChanged"), object: self )
            }
            
        }
        
        if (connected == false)
        {
            activityIndicatorView.startAnimating()
            
            let defaults = UserDefaults.standard
            var certificateId = defaults.string( forKey: "certificateId")
            
            if (certificateId == nil)
            {
                DispatchQueue.main.async {
                    self.logTextView?.text = "No identity available, searching bundle..."
                }
                //
                // No certificate ID has been stored in the user defaults; check to see if any .p12 files
                // exist in the bundle.
                //
                let myBundle = Bundle.main
                let myImages = myBundle.paths(forResourcesOfType: "p12" as String, inDirectory:nil)
                let uuid = UUID().uuidString;
                
                if (myImages.count > 0) {
                    //
                    // At least one PKCS12 file exists in the bundle.  Attempt to load the first one
                    // into the keychain (the others are ignored), and set the certificate ID in the
                    // user defaults as the filename.  If the PKCS12 file requires a passphrase,
                    // you'll need to provide that here; this code is written to expect that the
                    // PKCS12 file will not have a passphrase.
                    //
                    if let data = try? Data(contentsOf: URL(fileURLWithPath: myImages[0])) {
                        DispatchQueue.main.async {
                            self.logTextView?.text = "found identity \(myImages[0]), importing..."
                        }
                        if AWSIoTManager.importIdentity( fromPKCS12Data: data, passPhrase:"", certificateId:myImages[0]) {
                            //
                            // Set the certificate ID and ARN values to indicate that we have imported
                            // our identity from the PKCS12 file in the bundle.
                            //
                            defaults.set(myImages[0], forKey:"certificateId")
                            defaults.set("from-bundle", forKey:"certificateArn")
                            DispatchQueue.main.async {
                                self.logTextView?.text = "Using certificate: \(myImages[0]))"
                                self.iotDataManager.connect( withClientId: uuid, cleanSession:true, certificateId:myImages[0], statusCallback: mqttEventCallback)
                            }
                        }
                    }
                }
                certificateId = defaults.string( forKey: "certificateId")
                if (certificateId == nil) {
                    DispatchQueue.main.async {
                        self.logTextView?.text = "No identity found in bundle, creating one..."
                    }
                    //
                    // Now create and store the certificate ID in NSUserDefaults
                    //
                    let csrDictionary = [ "commonName":CertificateSigningRequestCommonName, "countryName":CertificateSigningRequestCountryName, "organizationName":CertificateSigningRequestOrganizationName, "organizationalUnitName":CertificateSigningRequestOrganizationalUnitName ]
                    
                    self.iotManager.createKeysAndCertificate(fromCsr: csrDictionary, callback: {  (response ) -> Void in
                        if (response != nil)
                        {
                            defaults.set(response?.certificateId, forKey:"certificateId")
                            defaults.set(response?.certificateArn, forKey:"certificateArn")
                            certificateId = response?.certificateId
                            print("response: [\(response)]")
                            
                            let attachPrincipalPolicyRequest = AWSIoTAttachPrincipalPolicyRequest()
                            attachPrincipalPolicyRequest?.policyName = PolicyName
                            attachPrincipalPolicyRequest?.principal = response?.certificateArn
                            //
                            // Attach the policy to the certificate
                            //
                            self.iot.attachPrincipalPolicy(attachPrincipalPolicyRequest!).continue(successBlock: { (task) -> AnyObject? in
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
                                    let delayTime = DispatchTime.now() + Double(Int64(2*Double(NSEC_PER_SEC))) / Double(NSEC_PER_SEC)
                                    DispatchQueue.main.asyncAfter( deadline: delayTime) {
                                        self.logTextView?.text = "Using certificate: \(certificateId!)"
                                        self.iotDataManager.connect( withClientId: uuid, cleanSession:true, certificateId:certificateId, statusCallback: mqttEventCallback)
                                    }
                                }
                                return nil
                            })
                        }
                        else
                        {
                            DispatchQueue.main.async {
                                sender.isEnabled = true
                                self.activityIndicatorView.stopAnimating()
                                self.logTextView?.text = "Unable to create keys and/or certificate, check values in Constants.swift"
                            }
                        }
                    } )
                }
            }
            else
            {
                let uuid = UUID().uuidString;
                
                //
                // Connect to the AWS IoT service
                //
                iotDataManager.connect( withClientId: uuid, cleanSession:true, certificateId:certificateId, statusCallback: mqttEventCallback)
            }
        }
        else
        {
            activityIndicatorView.startAnimating()
            logTextView?.text = "Disconnecting..."
            
            DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async{
                self.iotDataManager.disconnect();
                DispatchQueue.main.async {
                    self.activityIndicatorView.stopAnimating()
                    self.connected = false
                    sender.setTitle( "Connect", for:UIControlState())
                    sender.isEnabled = true
                }
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        logTextView?.resignFirstResponder()
        
        // Init IOT
        //
        // Set up Cognito
        //
        let credentialsProvider = AWSCognitoCredentialsProvider(regionType: AwsRegion, identityPoolId: CognitoIdentityPoolId)
        let configuration = AWSServiceConfiguration(region: AwsRegion, credentialsProvider: credentialsProvider)
        
        AWSServiceManager.default().defaultServiceConfiguration = configuration
        
        iotManager = AWSIoTManager.default()
        iot = AWSIoT.default()
        
        iotDataManager = AWSIoTDataManager.default()
        iotData = AWSIoTData.default()
        
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    @IBOutlet weak var publishSlider: UISlider!
    
    @IBAction func openDoorClicked(_ sender: UIButton) {
        print("openDoorClicked")
        
        let iotDataManager = AWSIoTDataManager.default()
        
        //        iotDataManager.publishString("\(sender.value)", onTopic:tabBarViewController.topic, qoS:.MessageDeliveryAttemptedAtMostOnce)
        var jsonData: Data = Data()
        
        let para:NSMutableDictionary = NSMutableDictionary()
        para.setValue("open", forKey: "event")
        
        do {
            jsonData = try JSONSerialization.data(withJSONObject: para, options: JSONSerialization.WritingOptions())
        } catch _ {
            
        }
        
        iotDataManager?.publishData(jsonData, onTopic:topic, qoS:.messageDeliveryAttemptedAtMostOnce)
    }
    
}
