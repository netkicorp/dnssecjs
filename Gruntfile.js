'use strict';

/* jshint -W106 */
module.exports = function(grunt) {

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    jshint: {
      files: [
        'lib/*.js',
        'Gruntfile.js',
        '!node_modules/**/*',
        '!browser/example/lib/**/*',
        '!browser/dist/**/*',
        '!browser/test/browserified_tests.js'
      ],
      options: {
        jshintrc: '.jshintrc'
      }
    },

    // remove all previous browserified builds
    clean: {
      dist: ['./browser/dist/**/*'],
      tests: ['./browser/test/browserified_tests.js']
    },

    // browserify everything
    browserify: {
      // This browserify build be used by users of the module. It contains a
      // UMD (universal module definition) and can be used via an AMD module
      // loader like RequireJS or by simply placing a script tag in the page,
      // which registers mymodule as a global var. You can see examples for both
      // usages in browser/example/index.html (script tag) and
      // browser/example/index-require.html (RequireJS).
      standalone: {
        src: [ '<%= pkg.name %>.js' ],
        dest: './browser/dist/<%= pkg.name %>.standalone.js',
        options: {
          //standalone: '<%= pkg.name %>'
          browserifyOptions: {
            debug: true,
            standalone: '<%= pkg.name %>'
          }
        }
      },
      // This browserify build can be required by other browserify modules that
      // have been created with an --external parameter. See
      // browser/test/index.html for an example.
      // require: {
      //   src: [ './<%= pkg.name %>.js' ],
      //   dest: './browser/dist/<%= pkg.name %>.require.js',
      //   options: {
      //     alias: [ './<%= pkg.name %>.js:' ]
      //   }
      // },
      // These are the browserified tests. We need to browserify the tests to be
      // able to run the mocha tests while writing the tests as clean, simple
      // CommonJS mocha tests (that is, without cross-platform boilerplate
      // code). This build will also include the testing libs chai, sinon and
      // sinon-chai but must not include the module under test.
      // tests: {
      //   src: [ 'browser/test/suite.js' ],
      //   dest: './browser/test/browserified_tests.js',
      //   options: {
      //     external: [ './<%= pkg.name %>.js' ],
      //     // Embed source map for tests
      //     debug: true
      //   }
      // }
    },

    // Uglify browser libs
    uglify: {
      dist: {
        files: {
          'browser/dist/<%= pkg.name %>.standalone.min.js':
              ['<%= browserify.standalone.dest %>'],
          'browser/dist/<%= pkg.name %>.require.min.js':
              ['<%= browserify.require.dest %>']
        }
      }
    },

    watch: {
      files: ['<%= jshint.files %>'],
      tasks: ['default']
    }
  });

  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-contrib-watch');

  grunt.registerTask('default', [
    'jshint',
    'clean',
    'browserify',
    'uglify'
  ]);
};
/* jshint +W106 */