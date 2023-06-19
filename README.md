# Roles and permissions in Laravel

<details>
  <summary><h2>Model generation and migrations</h2></summary>
  
- Generate models and migrations

      php artisan make:model Role -m
      php artisan make:model Permission -m
      php artisan make:migration create_users_permissions_table
      php artisan make:migration create_users_roles_table
      php artisan make:migration create_roles_permissions_table
  
- Edit migrations
  - **create_roles_table** migration file:
  
        <?php

        use Illuminate\Database\Migrations\Migration;
        use Illuminate\Database\Schema\Blueprint;
        use Illuminate\Support\Facades\Schema;

        return new class extends Migration
        {
            /**
             * Run the migrations.
             */
            public function up(): void
            {
                Schema::create('roles', function (Blueprint $table) {
                    $table->id();
                    $table->string('title', 30);
                    $table->string('name', 30);
                    $table->string('guard_name', 10);
                    $table->timestamps();
                });
            }

            /**
             * Reverse the migrations.
             */
            public function down(): void
            {
                Schema::dropIfExists('roles');
            }
        };

  - **create_permissions_table** migration file:

        <?php

        use Illuminate\Database\Migrations\Migration;
        use Illuminate\Database\Schema\Blueprint;
        use Illuminate\Support\Facades\Schema;

        return new class extends Migration
        {
            /**
             * Run the migrations.
             */
            public function up(): void
            {
                Schema::create('permissions', function (Blueprint $table) {
                    $table->id();
                    $table->string('title', 30);
                    $table->string('name', 30);
                    $table->string('guard_name', 10);
                    $table->timestamps();
                });
            }

            /**
             * Reverse the migrations.
             */
            public function down(): void
            {
                Schema::dropIfExists('permissions');
            }
        };
  - **create_users_permissions_table** migration file:
        
        <?php

        use Illuminate\Database\Migrations\Migration;
        use Illuminate\Database\Schema\Blueprint;
        use Illuminate\Support\Facades\Schema;

        return new class extends Migration
        {
            /**
             * Run the migrations.
             */
            public function up(): void
            {
                Schema::create('users_permissions', function (Blueprint $table) {
                    $table->foreignId('user_id')->constrained()->onDelete('cascade');
                    $table->foreignId('permission_id')->constrained()->onDelete('cascade');
                    $table->primary(['user_id','permission_id']);
                    $table->timestamps();
                });
            }

            /**
             * Reverse the migrations.
             */
            public function down(): void
            {
                Schema::dropIfExists('users_permissions');
            }
        };
        
  - **create_users_roles_table** migration file:
        
        <?php

        use Illuminate\Database\Migrations\Migration;
        use Illuminate\Database\Schema\Blueprint;
        use Illuminate\Support\Facades\Schema;

        return new class extends Migration
        {
            /**
             * Run the migrations.
             */
            public function up(): void
            {
                Schema::create('users_roles', function (Blueprint $table) {
                    $table->foreignId('user_id')->constrained()->onDelete('cascade');
                    $table->foreignId('role_id')->constrained()->onDelete('cascade');
                    $table->primary(['user_id','role_id']);
                    $table->timestamps();
                });
            }

            /**
             * Reverse the migrations.
             */
            public function down(): void
            {
                Schema::dropIfExists('users_roles');
            }
        };

  - **create_roles_permissions_table** migration file:
        
        <?php

        use Illuminate\Database\Migrations\Migration;
        use Illuminate\Database\Schema\Blueprint;
        use Illuminate\Support\Facades\Schema;

        return new class extends Migration
        {
            /**
             * Run the migrations.
             */
            public function up(): void
            {
                Schema::create('roles_permissions', function (Blueprint $table) {
                    $table->foreignId('role_id')->constrained()->onDelete('cascade');
                    $table->foreignId('permission_id')->constrained()->onDelete('cascade');;
                    $table->primary(['role_id','permission_id']);
                    $table->timestamps();
                });
            }

            /**
             * Reverse the migrations.
             */
            public function down(): void
            {
                Schema::dropIfExists('roles_permissions');
            }
        };

Now we can run: ```php artisan migrate```
</details>

<details>
  <summary><h2>Model relations</h2></summary>

- Models/role.php ```belongsToMany``` relation:
    
      public function permissions()
      {
          return $this->belongsToMany(Permission::class,'roles_permissions');
      }

- Models/permissions.php ```belongsToMany``` relation:

      public function roles()
      {
          return $this->belongsToMany(Role::class,'roles_permissions');
      }

</details>

<details>
  <summary><h2>Trait HasRolesAndPermissions for User model</h2></summary>

- Create new trait in **Traits** folder and name it ```HasRolesAndPermissions```
- Copy this code in newly created file:

      <?php

      namespace App\Traits;

      use App\Models\Role;
      use App\Models\Permission;

      trait HasRolesAndPermissions
      {
          public function roles(): mixed
          {
              return $this->belongsToMany(Role::class,'users_roles');
          }

          public function permissions(): mixed
          {
              return $this->belongsToMany(Permission::class,'users_permissions');
          }

          public function hasRole(mixed ... $roles): bool
          {
              foreach ($roles as $role) {
                  if ($this->roles->contains('name', $role)) {
                      return true;
                  }
              }
              return false;
          }

          public function hasPermission($permission): bool
          {
              return (bool) $this->permissions->where('name', $permission)->count();
          }

          public function hasPermissionTo($permission): bool
          {
              return $this->hasPermissionThroughRole($permission) || $this->hasPermission($permission->name);
          }

          public function hasPermissionThroughRole($permission): bool
          {
              foreach ($permission->roles as $role){
                  if($this->roles->contains($role)) {
                      return true;
                  }
              }
              return false;
          }

          public function getAllPermissions(array $permissions): mixed
          {
              return Permission::whereIn('name',$permissions)->get();
          }

          public function givePermissionsTo(mixed ... $permissions): static
          {
              $permissions = $this->getAllPermissions($permissions);
              if($permissions === null) {
                  return $this;
              }
              $this->permissions()->saveMany($permissions);
              return $this;
          }

          public function deletePermissions(mixed ... $permissions): static
          {
              $permissions = $this->getAllPermissions($permissions);
              $this->permissions()->detach($permissions);
              return $this;
          }

          public function refreshPermissions(mixed ... $permissions): \App\Models\User
          {
              $this->permissions()->detach();
              return $this->givePermissionsTo($permissions);
          }
      }

- Now add this trait to User model in ```Models/User.php```

      class User extends Authenticatable
      {
          use HasRolesAndPermissions; // this fragment

</details>

<details>
  <summary><h2>Add Custom blade directory for Roles and Permissions</h2></summary>

- Create new service provider 

      php artisan make:provider RolesServiceProvider
      php artisan make:provider PermissionServiceProvider

- Copy this code in **RolesServiceProvider** boot method

      Blade::directive('role', function ($role){
          return "<?php if(auth()->check() && auth()->user()->hasRole({$role})): ?>";
      });
      Blade::directive('endrole', function (){
          return "<?php endif; ?>";
      });
  
  Then you can use somthing like this in blade templates:
  
      @role('manager') // manager is role
        Manager Panel html here
      @endrole
  
- Copy this code in **PermissionServiceProvider** boot method
  
      try {
          Permission::get()->map(function ($permission) {
              Gate::define($permission->name, function ($user) use ($permission) {
                  return $user->hasPermissionTo($permission);
              });
          });
      } catch (\Exception $e) {
          report($e);
          return;
      }
  
  Then you can use somthing like that in blade templates:
  
        Gate::allows('edit-users'); //edit-user is permission
  
  
- **Don't forget** and add **RolesServiceProvider** and **PermissionServiceProvider** to providers list, in **config/app.php** file
</details>

<details>
  <summary><h2>Add Middlware for Roles and Permissions</h2></summary>

- Create **RoleMiddleware**
  
      php artisan make:middleware RoleMiddleware
  
- Copy this code in **RoleMiddleware**
  
      <?php

      namespace App\Http\Middleware;

      use Closure;
      use Illuminate\Http\Request;
      use Symfony\Component\HttpFoundation\Response;

      class RoleMiddleware
      {
          /**
           * Handle an incoming request.
           *
           * @param  Closure(Request): (Response)  $next
           */
          public function handle(Request $request, Closure $next, $role, $permission = null)
          {
              if(!auth()->user()->hasRole($role)) {
                  abort(403);
              }

              if($permission !== null && !auth()->user()->can($permission)) {
                  abort(403);
              }

              return $next($request);
          }
      }

- Before using this middlware, you need to add it in ```App\Http\Kernel.php``` file

      protected $middlewareAliases = [
              'auth' => \App\Http\Middleware\Authenticate::class,
              'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
              'auth.session' => \Illuminate\Session\Middleware\AuthenticateSession::class,
              'cache.headers' => \Illuminate\Http\Middleware\SetCacheHeaders::class,
              'can' => \Illuminate\Auth\Middleware\Authorize::class,
              'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
              'password.confirm' => \Illuminate\Auth\Middleware\RequirePassword::class,
              'signed' => \App\Http\Middleware\ValidateSignature::class,
              'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
              'verified' => \Illuminate\Auth\Middleware\EnsureEmailIsVerified::class,
              'role'  =>  \App\Http\Middleware\RoleMiddleware::class, // This is our middlware
          ];
      }

- Now you can use it in routing

      Route::group(['middleware' => 'auth'], function () {
          Route::group(['middleware' => 'role:admin'], function () { // This is our middlware
              Route::get('management/users', [UsersController::class, 'index'])->name('users');
          });
      });

</details>
