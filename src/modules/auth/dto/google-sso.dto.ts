import { IsString } from 'class-validator';

export class GoogleSsoDto {
  @IsString({ message: 'Google ID token is required' })
  idToken: string;
}
