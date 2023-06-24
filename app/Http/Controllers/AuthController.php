<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $fildes = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fildes['name'],
            'email' => $fildes['email'],
            'password' => bcrypt($fildes['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user'=> $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request){
        $fildes = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        //check email
        $user = User::where('email', $fildes['email'])->first();

        //check password
        if(!$user || !Hash::check($fildes['password'], $user->password)){
            return response([
                'message' => 'bad creds'
            ], 401);
        };

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user'=> $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function logout(Request $request){
        auth()->user()->tokens()->delete();

        return [
            'message' => 'logged out'
        ];
    }
}
