import AWS, { DynamoDBStreams } from 'aws-sdk';
import crypto from 'crypto'

export default class Cognito {
  private today = new Date()
  private config = {
    apiVersion: this.formatDate(this.today),
    region: 'ap-southeast-2',
  }
  private secretHash: string = '2f9a0sbem2isobs825q5osi11e6r7r7s7fj1pe4j7j0tdp299hf'
  private clientId: string = '1h1j55fi2nulm6hh6a8gcc64k3';

  private cognitoIdentity;

  constructor(){
    this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider(this.config)
  }

  public async signUpUser(username: string, password: string, userAttr: Array<any>): Promise<boolean> {
    
    var params = {
      ClientId: this.clientId, /* required */
      Password: password, /* required */
      Username: username, /* required */
      SecretHash: this.hashSecret(username),
      UserAttributes: userAttr,
    }

    try {
      const data = await this.cognitoIdentity.signUp(params).promise()
      console.log(data)
      return true
    } catch (error) {
      console.log(error)
      return false
    }
  }

  public  formatDate(date) {
    var d = new Date(date),
        month = '' + (d.getMonth() + 1),
        day = '' + d.getDate(),
        year = d.getFullYear();

    if (month.length < 2) 
        month = '0' + month;
    if (day.length < 2) 
        day = '0' + day;

    return [year, month, day].join('-');
}


  public async signInUser(username: string, password: string): Promise<boolean> {
    var params = {
      AuthFlow: 'USER_PASSWORD_AUTH', /* required */
      ClientId: this.clientId, /* required */
      AuthParameters: {
        'USERNAME': username,
        'PASSWORD': password,
        'SECRET_HASH': this.hashSecret(username)
      },
    }

    try {
      let data = await this.cognitoIdentity.initiateAuth(params).promise();
      console.log(data); 
      return true;
    } catch (error) {
      console.log(error)
      return false;
    }
  }

  public async confirmSignUp(username: string, code: string): Promise<boolean> {
    var params = {
      ClientId: this.clientId,
      ConfirmationCode: code,
      Username: username,
      SecretHash: this.hashSecret(username),
    };

    try {
      const cognitoResp = await this.cognitoIdentity.confirmSignUp(params).promise();
      console.log(cognitoResp)

      return true
    } catch (error) {
      console.log("error", error)
      return false
    }
  }


  public async getUser(code: string): Promise<boolean> {
    var params = {
      AccessToken: code,
    };
    console.log("Trying")
    try {
      const cognitoResp = await this.cognitoIdentity.getUser(params).promise();
      console.log(cognitoResp)
      return true
    } catch (error) {
      console.log("error", error)
      return false
    }
  }

  public async forgotPassword(username): Promise<boolean> {
    var params = {
      ClientId: this.clientId, /* required */
      Username: username, /* required */
      SecretHash: this.hashSecret(username),
    }

    try {
      const data = await this.cognitoIdentity.forgotPassword(params).promise();
      console.log(data);
      return true
    } catch (error) {
      console.log(error);
      return false;
    }
  }

  public async confirmNewPassword(username: string, password: string, code: string): Promise<boolean> {
    var params = {
      ClientId: this.clientId, /* required */
      ConfirmationCode: code, /* required */
      Password: password, /* required */
      Username: username, /* required */
      SecretHash: this.hashSecret(username),
    };

    try {
      const data = await this. cognitoIdentity.confirmForgotPassword(params).promise();
      console.log(data);
      return true;
    } catch (error) {
      console.log(error);
      return false;
    }
  }

  private hashSecret(username: string): string {
    return crypto.createHmac('SHA256', this.secretHash)
    .update(username + this.clientId)
    .digest('base64')  
  } 
}