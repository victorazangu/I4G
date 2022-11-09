<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        //validate data
        $validatedData = $request->validate([
            'first_name' => 'required|max:55',
            'last_name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'country' => 'required',
            'adresss1' => 'required',
            'adresss2' => 'required',
            'city' => 'required',
            'state' => 'required',
            'zip' => 'required',
            'password' => 'required|confirmed'
        ]);
      
        //hash password
        $validatedData['password'] = bcrypt($request->password);
        

        //create user
        $user = User::create($validatedData);
       

        //return response
        return response()->json(
            [
                "status" => 1,
                "message" => "User created successfully",
                "data" => $user

            ]
        );    
    }
    public function login(Request $request)
    {
        //validate date
        $loginData = $request->validate(
            [
                'email' => 'email|required',
                'password' => 'required'
            ]
        );
        //check for credentials
        if (!auth()->attempt($loginData)) {
            return response(
                [ 
                    "status" => 0,
                    'message' => 'Invalid Credentials'
                ]
            );
        }

        //logged in user data
        $user = auth()->user();

       //create access token
        $accessToken = $user->createToken('authToken')->accessToken;
        $user['accessToken']=$accessToken ;

        return response(
            [
                'status' => 1,
                'message' => "You have loged in  successfully",
                'data' => $user,
            ]
        );
    }

    public function profile()
    {
       $user_data = auth()->user(); 
    

        return response()->json([
            "status" => 1,
            "message" => "User ",
            "User data" => $user_data
        ]);

    }

    public function logout(Request $request)
    {
        // get token value
        $token = $request->user()->token();

        // revoke this token value
        $token->revoke();

        return response()->json([
            "status" => 1,
            "message" => "User logged out successfully"
        ]);
    }

    
}
