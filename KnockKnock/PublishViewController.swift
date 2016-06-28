/*
* Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

import UIKit
import AWSIoT

class PublishViewController: UIViewController {

    @IBOutlet weak var publishSlider: UISlider!

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    @IBAction func sliderValueChanged(sender: UISlider) {
        print("\(sender.value)")

        let iotDataManager = AWSIoTDataManager.defaultIoTDataManager()
        let tabBarViewController = tabBarController as! IoTSampleTabBarController

//        iotDataManager.publishString("\(sender.value)", onTopic:tabBarViewController.topic, qoS:.MessageDeliveryAttemptedAtMostOnce)
        var jsonData: NSData = NSData()
        
        let para:NSMutableDictionary = NSMutableDictionary()
        para.setValue("open", forKey: "event")
        
        do {
            jsonData = try NSJSONSerialization.dataWithJSONObject(para, options: NSJSONWritingOptions())
        } catch _ {
            
        }
        
        iotDataManager.publishData(jsonData, onTopic:tabBarViewController.topic, qoS:.MessageDeliveryAttemptedAtMostOnce)
    }
}