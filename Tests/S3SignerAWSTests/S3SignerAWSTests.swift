//
//  S3SignerAWSTests.swift
//  S3SignerAWSTests
//
//  Created by Justin H. Moehringer on 10/7/16.
//
//

import XCTest
import Foundation
import CryptoSwift
@testable import S3SignerAWS

let accessKey = "AKIAIOSFODNN7EXAMPLE"
let testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

var signer: S3SignerAWS = S3SignerAWS(accessKey: accessKey, secretKey: testSecretKey, region: Region.usEast1_Virginia)

extension S3SignerAWSTests {
    public static var allTests: [(String, (S3SignerAWSTests) -> () throws -> Void)] {
        return [
            ("testV4AuthHeaderPut", testV4AuthHeaderPut),
            ("testV4AuthHeaderGetWithMultipleParams", testV4AuthHeaderGetWithMultipleParams),
            ("testV4AuthHeaderGetWithParam", testV4AuthHeaderGetWithParam),
            ("testV4AuthHeaderGet", testV4AuthHeaderGet),
            ("testV4PresignedURL", testV4PresignedURL),
            //("testFinalQueryURLV2", testFinalQueryURLV2), // This test fails obtaining reponse (gets nil), or 403 after url fix. Access key and url fix needed?
            //("testFinalAuthHeaderv4Get", testFinalAuthHeaderv4Get), // Same problem
            ("testHash", testHash),
            ("testHMAC", testHMAC),
            ("testPerformanceExample", testPerformanceExample)
        ]
    }
}


class S3SignerAWSTests: XCTestCase {

    //Testing Data from AWS

    let shortDate = "20130524"
    let longDate = "20130524T000000Z"

    let regionName = "us-east-1"

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

   func testV4AuthHeaderPut() {
       let urlString: String = "https://examplebucket.s3.amazonaws.com/test$file.text"
       let url: URL = URL(string: urlString)!
       let updatedHeaders: [String:String] = ["x-amz-storage-class":"REDUCED_REDUNDANCY", "host":"examplebucket.s3.amazonaws.com", "x-amz-date":"20130524T000000Z", "x-amz-content-sha256":"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072", "date":"Fri, 24 May 2013 00:00:00 GMT"]
       let bodyDigest = "Welcome to Amazon S3.".sha256()

       let canonicalRequestHex = signer.TcreateCanonicalRequest(httpMethod: .put, url: url, pathEncoding: CharacterSet(charactersIn: "$").inverted, queryEncoding: CharacterSet.urlQueryAllowed, headers: updatedHeaders, bodyDigest: bodyDigest)

       let correctHexString = ["PUT", "/test%24file.text", "", "date:Fri, 24 May 2013 00:00:00 GMT", "host:examplebucket.s3.amazonaws.com", "x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072", "x-amz-date:20130524T000000Z", "x-amz-storage-class:REDUCED_REDUNDANCY", "", "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"].joined(separator: "\n")

       XCTAssert(canonicalRequestHex == correctHexString, "CanonicalRequest Does Not Match\nExpected:\n\(correctHexString)\nActual:\n\(canonicalRequestHex)\n")

       let stringToSign = signer.TcreateStringToSign(canonicalRequest: canonicalRequestHex, timeStampLong: longDate, timeStampShort: shortDate)

       let correctStringToSign = ["AWS4-HMAC-SHA256", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"].joined(separator: "\n")

       XCTAssert(stringToSign == correctStringToSign, "StringToSign Does Not Match\nExpected:\n\(correctStringToSign)\nActual:\n\(stringToSign)\n")

       let signature = signer.TgetSignature(stringToSign: stringToSign, timeStampShort: shortDate)
       let correctSignature = "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"

       XCTAssert(signature == correctSignature, "Signature Does Not match\nExpected:\n\(correctSignature)\nActual:\n\(signature)\n")
       let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(signer.TcredentialScope(timeStampShort: shortDate, regionName: signer.region.rawValue)), SignedHeaders=\(signer.TsignedHeaders(headers: updatedHeaders)), Signature=\(signature)"

       let correctAuthHeader = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"

       XCTAssert(authHeader == correctAuthHeader, "Auth Header Does Not match\nExpected:\n\(correctAuthHeader)\nActual:\n\(authHeader)\n")
   }

   func testV4AuthHeaderGetWithMultipleParams() {
       let urlString = "https://examplebucket.s3.amazonaws.com?max-keys=2&prefix=J"
       let url = URL(string: urlString)!
       let updatedHeaders = ["host":"examplebucket.s3.amazonaws.com", "x-amz-content-sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date":"20130524T000000Z"]
       let bodyDigest = "".sha256()

       let canonRequest = signer.TcreateCanonicalRequest(httpMethod: .get, url: url, pathEncoding: CharacterSet.urlPathAllowed, queryEncoding: CharacterSet.urlQueryAllowed, headers: updatedHeaders, bodyDigest: bodyDigest)

       let correctHexString = ["GET", "/", "max-keys=2&prefix=J", "host:examplebucket.s3.amazonaws.com", "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date:20130524T000000Z", "", "host;x-amz-content-sha256;x-amz-date", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].joined(separator: "\n")

       XCTAssert(canonRequest == correctHexString, "Canonical Request Does Not Match")

       let stringToSign = signer.TcreateStringToSign(canonicalRequest: canonRequest, timeStampLong: longDate, timeStampShort: shortDate)

       let correctStringToSign = ["AWS4-HMAC-SHA256", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7"].joined(separator: "\n")

       XCTAssert(stringToSign == correctStringToSign, "StringToSign Does Not Match")

       let signature = signer.TgetSignature(stringToSign: stringToSign, timeStampShort: shortDate)

       XCTAssert(signature == "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", "Signature Does Not Match")

       let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(signer.TcredentialScope(timeStampShort: shortDate, regionName: signer.region.rawValue)), SignedHeaders=\(signer.TsignedHeaders(headers: updatedHeaders)), Signature=\(signature)"

       XCTAssert(authHeader == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", "Auth Header Does Not Match")
       }

   func testV4AuthHeaderGetWithParam() {
       let urlString = "https://examplebucket.s3.amazonaws.com?lifecycle="
       let url = URL(string: urlString)!
       let updatedHeaders = ["host":"examplebucket.s3.amazonaws.com", "x-amz-content-sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date":"20130524T000000Z"]
       let bodyDigest = "".sha256()

       let canonicalRequestHex = signer.TcreateCanonicalRequest(httpMethod: .get, url: url, pathEncoding: CharacterSet.urlPathAllowed, queryEncoding: CharacterSet.urlQueryAllowed, headers: updatedHeaders, bodyDigest: bodyDigest)

       let correctHexString = ["GET", "/", "lifecycle=", "host:examplebucket.s3.amazonaws.com", "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date:20130524T000000Z", "", "host;x-amz-content-sha256;x-amz-date", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].joined(separator: "\n")

       XCTAssert(canonicalRequestHex == correctHexString, "Canonical Request does not match")

       let stringToSign = signer.TcreateStringToSign(canonicalRequest: canonicalRequestHex, timeStampLong: longDate, timeStampShort: shortDate)

       let correctStringToSign = ["AWS4-HMAC-SHA256", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca"].joined(separator: "\n")

       XCTAssert(stringToSign == correctStringToSign, "StringToSign Does not match")

       let signature = signer.TgetSignature(stringToSign: stringToSign, timeStampShort: shortDate)

       XCTAssert(signature == "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", "signature does not match")

       let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(signer.TcredentialScope(timeStampShort: shortDate, regionName: signer.region.rawValue)), SignedHeaders=\(signer.TsignedHeaders(headers: updatedHeaders)), Signature=\(signature)"

       XCTAssert(authHeader == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", "Auth Headers Do Not Match")
       }

   func testV4AuthHeaderGet() {
       let urlString: String = "https://examplebucket.s3.amazonaws.com/test.txt"
       let url: URL = URL(string: urlString)!
       let updatedHeaders: [String:String] = ["range":"bytes=0-9", "host":"examplebucket.s3.amazonaws.com", "x-amz-date":"20130524T000000Z", "x-amz-content-sha256" : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
       let bodyDigest: String = "".sha256()

       let canonicalRequestHex = signer.TcreateCanonicalRequest(httpMethod: .get, url: url, pathEncoding: CharacterSet.urlPathAllowed, queryEncoding: CharacterSet.urlQueryAllowed, headers: updatedHeaders, bodyDigest: bodyDigest)

       let correctHexString = ["GET", "/test.txt", "", "host:examplebucket.s3.amazonaws.com", "range:bytes=0-9", "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date:20130524T000000Z", "", "host;range;x-amz-content-sha256;x-amz-date", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].joined(separator: "\n")

       XCTAssert(canonicalRequestHex == correctHexString, "CanonicalRequest Does Not Match")

       let stringToSign = signer.TcreateStringToSign(canonicalRequest: canonicalRequestHex, timeStampLong: longDate, timeStampShort: shortDate)

       let correctStringToSign = ["AWS4-HMAC-SHA256", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"].joined(separator: "\n")

       XCTAssert(stringToSign == correctStringToSign, "stringToSign Does not match")

       let signature = signer.TgetSignature(stringToSign: stringToSign, timeStampShort: shortDate)

       XCTAssert(signature == "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "Signature Does not match")

       let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(signer.TcredentialScope(timeStampShort: shortDate, regionName: signer.region.rawValue)), SignedHeaders=\(signer.TsignedHeaders(headers: updatedHeaders)), Signature=\(signature)"

       XCTAssert(authHeader == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "Auth Headers Do Not Match")
   }

   func testV4PresignedURL() {
       let urlString = "https://examplebucket.s3.amazonaws.com/test.txt"

       let expireTime = TimeFromNow.custom(86400)

       let paramURLString = "\(urlString)?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=\(accessKey)/\(signer.TcredentialScope(timeStampShort: shortDate, regionName: signer.region.rawValue).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)&X-Amz-Date=\(longDate)&X-Amz-Expires=\(expireTime.v4Expiration)&X-Amz-SignedHeaders=host"
       let url = URL(string: paramURLString)!

       let canonHex = ["GET", "\(url.path)", "\(url.query!.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!)", "host:examplebucket.s3.amazonaws.com", "", "host", "UNSIGNED-PAYLOAD"].joined(separator: "\n")

       let correctHexString = ["GET", "/test.txt", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host", "host:examplebucket.s3.amazonaws.com", "", "host", "UNSIGNED-PAYLOAD"].joined(separator: "\n")

       XCTAssert(canonHex == correctHexString, "CanonRequest Does Not match")

       let stringToSign = signer.TcreateStringToSign(canonicalRequest: canonHex, timeStampLong: longDate, timeStampShort: shortDate)

       let correctStringToSign = ["AWS4-HMAC-SHA256", "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", "3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04"].joined(separator: "\n")

       XCTAssert(stringToSign == correctStringToSign, "String To Sign Does Not Match")

       let signature = signer.TgetSignature(stringToSign: stringToSign, timeStampShort: shortDate)

       XCTAssert(signature == "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", "Signature Does not match")

       let preSignedURL = "\(urlString)?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=\(accessKey)%2F\(signer.TcredentialScope(timeStampShort: shortDate, regionName: signer.region.rawValue).addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!)&X-Amz-Date=\(longDate)&X-Amz-Expires=\(expireTime.v4Expiration)&X-Amz-SignedHeaders=host&X-Amz-Signature=\(signature)"

       XCTAssert(preSignedURL == "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", "PreSigned URL does not match")

   }

  //  func testFinalQueryURLV2() {
  //      let testExpectation = expectation(description: "Wait for HTTP Response")
   //
  //      let presignedURL = try! signer.presignedURLV2(urlString: "s3URL", expiration: TimeFromNow.custom(1000)) // value of URL string possibly should be replaced
  //      print(presignedURL)
  //      let url = URL(string: presignedURL)!
   //
  //      var request = URLRequest(url: url)
   //
  //      request.httpMethod = "GET"
  //      print(request)
  //      let session = URLSession(configuration: .default)
   //
  //      let task = session.dataTask(with: request, completionHandler: { data, response, error in
  //          print("before response")
  //          sleep(5)
  //          let response = response as! HTTPURLResponse // This line fails...
  //          print("after response")
  //          print(response.allHeaderFields)
  //          print(response.url)
  //          XCTAssert(response.statusCode == 200, "Wrong response code, response code recieved = \(response.statusCode)")
   //
  //          testExpectation.fulfill()
   //
  //      })
  //      print(task)
  //      task.resume()
  //      print(task)
  //      waitForExpectations(timeout: 10000) { (error) in
  //          if let error = error {
  //              XCTFail("expectation error: \(error)")
  //          }
  //      }
  //      print("end")
   //
  //  }

  //  func testFinalAuthHeaderv4Get() {
  //      let testExpectation = expectation(description: "Wait for HTTP Response")
  //      let urlString = "s3URL" // Needs to be changed to actual URL?
  //      let headers = try! signer.authHeaderV4(httpMethod: .get, urlString: urlString, headers: [:], payload: Payload.bytes("".bytes))
   //
  //      let url = URL(string: urlString)!
   //
  //      var request = URLRequest(url: url)
   //
  //      request.httpMethod = "GET"
   //
  //      for header in headers {
  //          request.setValue(header.value, forHTTPHeaderField: header.key)
  //      }
   //
  //      let session = URLSession(configuration: .default)
   //
  //      let task = session.dataTask(with: request, completionHandler: { data, response, error in
   //
  //          let response = response as! HTTPURLResponse
   //
   //
  //          XCTAssert(response.statusCode == 200, "Wrong response code, response code recieved = \(response.statusCode)")
   //
  //          testExpectation.fulfill()
   //
  //      })
  //      task.resume()
   //
  //      waitForExpectations(timeout: 1) { (error) in
  //          if let error = error {
  //              XCTFail("expectation error: \(error)")
  //          }
  //      }
  //  }

  func testHash() {
    let expectedHash1 = "1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab3"
    let res1 = [0,1,2,3,4,5,6,7,8,9].sha256().toHexString()
    XCTAssert(res1 == expectedHash1, "Hash is wrong:\n Expected:\n \(expectedHash1)\n Actual:\n \(res1)")
    let expectedHash2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    let res2 = "".sha256()
    XCTAssert(res2 == expectedHash2, "Hash is wrong:\n Expected:\n \(expectedHash2)\n Actual:\n \(res2)")
    let expectedMD5Digest = "xWvVSA9uVBPLYqCtlmZhOg=="
    let MD5Digest = [0,1,2,3,4,5,6,7,8,9].md5().toBase64()!
    XCTAssert(MD5Digest == expectedMD5Digest, "Hash is wrong:\n Expected:\n \(expectedMD5Digest)\n Actual:\n \(MD5Digest)")
    let expectedCanonRequestHash = "1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047"
    let canonRequestHash = "request".sha256()
    XCTAssert(canonRequestHash == expectedCanonRequestHash, "Hash is wrong:\n Expected:\n \(expectedCanonRequestHash)\n Actual:\n \(canonRequestHash)")

  }

  func testHMAC() throws {
    let expectedStringToSignBytes : [UInt8] = [71, 69, 84, 32, 116, 101, 115, 116, 32, 114, 101, 113, 117, 101, 115, 116, 32, 103, 111, 101, 115, 32, 104, 101, 114, 101]
    let stringToSignBytes = ["GET test request goes here"].joined(separator: "\n").data(using: String.Encoding.utf8)!.bytes
    XCTAssert(stringToSignBytes == expectedStringToSignBytes, "Bytes of string are wrong:\n Expected:\n \(expectedStringToSignBytes)\n Actual:\n \(stringToSignBytes)")
    let expectedSignature = Optional("o3PZtoSiZxiLIVeZMErM5j9uFIQ=")
    let signature = try! HMAC(key: [UInt8]("SecretKey".utf8), variant: .sha1).authenticate(stringToSignBytes).toBase64()!.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)
    XCTAssert(signature == expectedSignature, "Signature is wrong:\n Expected:\n \(expectedSignature)\n Actual:\n \(signature)")
  }

   func testPerformanceExample() {
       // This is an example of a performance test case.
       self.measure {
       }
   }

}
