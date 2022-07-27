import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthDto {
  @IsEmail()
  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @MinLength(5)
  @IsString()
  @IsNotEmpty()
  readonly password: string;
}
