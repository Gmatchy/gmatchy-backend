import { IsPhoneNumber, IsString, Length } from 'class-validator';

export class VerifyOtpDto {
  @IsPhoneNumber(undefined, { message: 'Please provide a valid phone number' })
  phone: string;

  @IsString()
  @Length(4, 6, { message: 'OTP must be between 4 and 6 digits' })
  otp: string;
}
