export class RegisterDto {
  email: string;
  password: string;
  firstname: string;
  lastname: string;
  displayName: string;
  imageUrl?: string;

  constructor(partial: Partial<RegisterDto>) {
    Object.assign(this, partial);
  }
}
