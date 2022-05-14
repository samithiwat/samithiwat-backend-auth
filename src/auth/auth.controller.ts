import { Controller } from '@nestjs/common';
import { AuthService } from './services/auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @MessagePattern('createAuth')
  // create(@Payload() createAuthDto: CreateAuthDto) {
  //   return this.authService.create(createAuthDto);
  // }

  // @MessagePattern('findAllAuth')
  // findAll() {
  //   return this.authService.findAll();
  // }

  // @MessagePattern('findOneAuth')
  // findOne(@Payload() id: number) {
  //   return this.authService.findOne(id);
  // }

  // @MessagePattern('updateAuth')
  // update(@Payload() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(updateAuthDto.id, updateAuthDto);
  // }

  // @MessagePattern('removeAuth')
  // remove(@Payload() id: number) {
  //   return this.authService.remove(id);
  // }
}
