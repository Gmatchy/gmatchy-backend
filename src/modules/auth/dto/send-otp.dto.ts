import { IsPhoneNumber } from 'class-validator';

export class SendOtpDto {
  @IsPhoneNumber(undefined, { message: 'Please provide a valid phone number' })
  phone: string;
}
