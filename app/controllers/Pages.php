<?php

class Pages extends Controller
{
    public function __construct()
    {

    }

    public function index()
    {
        $data = [
            'title' => 'SharePosts',
            'description' => 'Simple social network',
        ];

        $this->view('pages/index', $data);
    }

    public function about()
    {
        $data = [
            'title' => 'About US',
            'description' => 'App to share posts with other users',
        ];
        $this->view('pages/about', $data);
    }
}
