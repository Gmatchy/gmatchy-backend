import {
  IsEmail,
  IsString,
  MinLength,
  IsDateString,
  IsPhoneNumber,
  IsEnum,
  IsOptional,
  MaxLength,
} from 'class-validator';

export enum Sex {
  Male = 'male',
  Female = 'female',
}

export class RegisterDto {
  @IsString()
  @MinLength(2, { message: 'Name must be at least 2 characters long' })
  @MaxLength(50, { message: 'Name must not exceed 50 characters' })
  name: string;

  @IsDateString({}, { message: 'Please provide a valid birth date (YYYY-MM-DD)' })
  birthdate: string;

  @IsPhoneNumber(undefined, { message: 'Please provide a valid phone number' })
  phone: string;

  @IsEnum(Sex, { message: 'Sex must be male or female' })
  sex: Sex;

  @IsOptional()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email?: string;

  @IsOptional()
  @IsString()
  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  password?: string;
}
