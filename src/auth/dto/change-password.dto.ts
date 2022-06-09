export class ChangePasswordDto {
  userId: number;
  oldPassword: string;
  newPassword: string;

  constructor(partial: Partial<ChangePasswordDto>) {
    Object.assign(this, partial);
  }
}
